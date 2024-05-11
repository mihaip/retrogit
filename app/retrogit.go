package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	log_ "log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/delay"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/mail"
	"google.golang.org/appengine/v2/urlfetch"

	"github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var router *mux.Router
var githubOauthConfig oauth2.Config
var githubOauthPublicConfig oauth2.Config
var timezones Timezones
var sessionStore *sessions.CookieStore
var sessionConfig SessionConfig
var templates map[string]*Template

func main() {
	templates = loadTemplates()
	timezones = initTimezones()
	sessionStore, sessionConfig = initSession()
	githubOauthConfig = initGithubOAuthConfig(true)
	githubOauthPublicConfig = initGithubOAuthConfig(false)

	router = mux.NewRouter()
	router.Handle("/", AppHandler(indexHandler)).Name("index")
	router.Handle("/faq", AppHandler(faqHandler)).Name("faq")

	router.Handle("/session/sign-in", AppHandler(signInHandler)).Name("sign-in").Methods("POST")
	router.Handle("/session/sign-out", AppHandler(signOutHandler)).Name("sign-out").Methods("POST")
	router.Handle("/github/callback", AppHandler(githubOAuthCallbackHandler))

	router.Handle("/digest/view", SignedInAppHandler(viewDigestHandler)).Name("view-digest")
	router.Handle("/digest/send", SignedInAppHandler(sendDigestHandler)).Name("send-digest").Methods("POST")
	router.Handle("/digest/cron", AppHandler(digestCronHandler))

	router.Handle("/account/settings", SignedInAppHandler(settingsHandler)).Name("settings").Methods("GET")
	router.Handle("/account/settings", SignedInAppHandler(saveSettingsHandler)).Name("save-settings").Methods("POST")
	router.Handle("/account/set-initial-timezone", SignedInAppHandler(setInitialTimezoneHandler)).Name("set-initial-timezone").Methods("POST")
	router.Handle("/account/delete", SignedInAppHandler(deleteAccountHandler)).Name("delete-account").Methods("POST")

	router.Handle("/admin/users", AppHandler(usersAdminHandler)).Name("users-admin")
	router.Handle("/admin/digest", AppHandler(digestAdminHandler)).Name("digest-admin")
	router.Handle("/admin/repos", AppHandler(reposAdminHandler)).Name("repos-admin")
	router.Handle("/admin/delete-account", AppHandler(deleteAccountAdminHandler)).Name("delete-account-admin")
	http.Handle("/", router)

	appengine.Main()
}

func initGithubOAuthConfig(includePrivateRepos bool) (config oauth2.Config) {
	path := "config/github-oauth"
	if appengine.IsDevAppServer() {
		path += "-dev"
	}
	path += ".json"
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log_.Panicf("Could not read GitHub OAuth config from %s: %s", path, err.Error())
	}
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		log_.Panicf("Could not parse GitHub OAuth config %s: %s", configBytes, err.Error())
	}
	repoScopeModifier := ""
	if !includePrivateRepos {
		repoScopeModifier = "public_"
	}
	config.Scopes = []string{fmt.Sprintf("%srepo", repoScopeModifier), "user:email"}
	config.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	}
	return
}

func indexHandler(w http.ResponseWriter, r *http.Request) *AppError {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId, ok := session.Values[sessionConfig.UserIdKey].(int64)
	if !ok {
		data := map[string]interface{}{
			"ContinueUrl": r.FormValue("continue_url"),
		}
		return templates["index-signed-out"].Render(w, data)
	}
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if account == nil {
		// Can't look up the account, session cookie must be invalid, clear it.
		session.Options.MaxAge = -1
		session.Save(r, w)
		return RedirectToRoute("index")
	}
	if err != nil {
		return InternalError(err, "Could not look up account")
	}

	githubClient := githubOAuthClient(c, account.OAuthToken)

	var wg sync.WaitGroup
	wg.Add(2)
	var user *github.User
	var userErr error
	var emailAddress string
	var emailAddressErr error
	go func() {
		user, _, userErr = githubClient.Users.Get(c, "")
		wg.Done()
	}()
	go func() {
		emailAddress, emailAddressErr = account.GetDigestEmailAddress(c, githubClient)
		wg.Done()
	}()
	wg.Wait()
	if userErr != nil {
		return GitHubFetchError(userErr, "user")
	}
	if emailAddressErr != nil {
		return GitHubFetchError(userErr, "emails")
	}

	var repositoryCount string
	if len(account.ExcludedRepoIds) > 0 {
		repositoryCount = fmt.Sprintf("all but %d", len(account.ExcludedRepoIds))
	} else {
		repositoryCount = "all"
	}

	var settingsSummary = map[string]interface{}{
		"Frequency":       account.Frequency,
		"RepositoryCount": repositoryCount,
		"EmailAddress":    emailAddress,
	}
	var data = map[string]interface{}{
		"User":            user,
		"SettingsSummary": settingsSummary,
		"DetectTimezone":  !account.HasTimezoneSet,
	}
	return templates["index"].Render(w, data, &AppSignedInState{
		Account:        account,
		GitHubClient:   githubClient,
		session:        session,
		responseWriter: w,
		request:        r,
	})
}

func faqHandler(w http.ResponseWriter, r *http.Request) *AppError {
	return templates["faq"].Render(w, nil)
}

func signInHandler(w http.ResponseWriter, r *http.Request) *AppError {
	config := &githubOauthConfig
	if r.FormValue("include_private") != "1" {
		config = &githubOauthPublicConfig
	}
	authCodeUrl := config.AuthCodeURL("")
	if continueUrl := r.FormValue("continue_url"); continueUrl != "" {
		if parsedAuthCodeUrl, err := url.Parse(authCodeUrl); err == nil {
			authCodeQuery := parsedAuthCodeUrl.Query()
			redirectUrl := authCodeQuery.Get("redirect_uri")
			if parsedRedirectUrl, err := url.Parse(redirectUrl); err == nil {
				redirectUrlQuery := parsedRedirectUrl.Query()
				redirectUrlQuery.Set("continue_url", continueUrl)
				parsedRedirectUrl.RawQuery = redirectUrlQuery.Encode()
				authCodeQuery.Set("redirect_uri", parsedRedirectUrl.String())
				parsedAuthCodeUrl.RawQuery = authCodeQuery.Encode()
				authCodeUrl = parsedAuthCodeUrl.String()
			}
		}
	}
	return RedirectToUrl(authCodeUrl)
}

func signOutHandler(w http.ResponseWriter, r *http.Request) *AppError {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	session.Options.MaxAge = -1
	session.Save(r, w)
	return RedirectToRoute("index")
}

func viewDigestHandler(w http.ResponseWriter, r *http.Request, state *AppSignedInState) *AppError {
	c := appengine.NewContext(r)
	digest, err := newDigest(c, state.GitHubClient, state.Account)
	if err != nil {
		return GitHubFetchError(err, "digest")
	}
	var data = map[string]interface{}{
		"Digest": digest,
	}
	return templates["digest-page"].Render(w, data, state)
}

func sendDigestHandler(w http.ResponseWriter, r *http.Request, state *AppSignedInState) *AppError {
	c := appengine.NewContext(r)
	sent, err := sendDigestForAccount(state.Account, c)
	if err != nil {
		return InternalError(err, "Could not send digest")
	}

	if sent {
		state.AddFlash("Digest emailed!")
	} else {
		state.AddFlash("No digest was sent, it was empty or disabled.")
	}
	return RedirectToRoute("index")
}

func digestCronHandler(w http.ResponseWriter, r *http.Request) *AppError {
	c := appengine.NewContext(r)
	accounts, err := getAllAccounts(c)
	if err != nil {
		return InternalError(err, "Could not look up accounts")
	}
	for _, account := range accounts {
		if account.Frequency == "weekly" {
			now := time.Now().In(account.TimezoneLocation)
			if now.Weekday() != account.WeeklyDay {
				log.Infof(c, "Skipping %d, since it wants weekly digests on %ss and today is a %s.",
					account.GitHubUserId, account.WeeklyDay, now.Weekday())
				continue
			}
		}
		log.Infof(c, "Enqueing task for %d...", account.GitHubUserId)
		sendDigestForAccountFunc.Call(c, account.GitHubUserId)
	}
	fmt.Fprint(w, "Done")
	return nil
}

var sendDigestForAccountFunc = delay.Func(
	"sendDigestForAccount",
	func(c context.Context, githubUserId int64) error {
		log.Infof(c, "Sending digest for %d...", githubUserId)
		account, err := getAccount(c, githubUserId)
		if err != nil {
			log.Errorf(c, "  Error looking up account: %s", err.Error())
			return err
		}
		sent, err := sendDigestForAccount(account, c)
		if err != nil {
			log.Errorf(c, "  Error: %s", err.Error())
			if !appengine.IsDevAppServer() {
				sendDigestErrorMail(err, c, githubUserId)
			}
		} else if sent {
			log.Infof(c, "  Sent!")
		} else {
			log.Infof(c, "  Not sent, digest was empty")
		}
		return err
	})

func sendDigestErrorMail(e error, c context.Context, gitHubUserId int64) {
	if strings.Contains(e.Error(), ": 502") {
		// Ignore 502s from GitHub, there's nothing we do about them.
		return
	}
	if appengine.IsTimeoutError(e) ||
		strings.Contains(e.Error(), "DEADLINE_EXCEEDED") {
		// Ignore deadline exceeded errors for URL fetches
		return
	}

	errorMessage := &mail.Message{
		Sender:  "RetroGit Admin <digests@retrogit.com>",
		To:      []string{"mihai.parparita@gmail.com"},
		Subject: fmt.Sprintf("RetroGit Digest Send Error for %d", gitHubUserId),
		Body:    fmt.Sprintf("Error: %s", e),
	}
	err := mail.Send(c, errorMessage)
	if err != nil {
		log.Errorf(c, "Error %s sending error email.", err.Error())
	}
}

func sendDigestForAccount(account *Account, c context.Context) (bool, error) {
	githubClient := githubOAuthClient(c, account.OAuthToken)

	emailAddress, err := account.GetDigestEmailAddress(c, githubClient)
	if err != nil {
		if gitHubError, ok := (err).(*github.ErrorResponse); ok {
			gitHubStatus := gitHubError.Response.StatusCode
			if gitHubStatus == http.StatusUnauthorized ||
				gitHubStatus == http.StatusForbidden {
				log.Errorf(c, "  GitHub auth error while getting email adddress, skipping: %s", err.Error())
				return false, nil
			}
		}

		return false, err
	}
	if emailAddress == "disabled" {
		return false, nil
	}

	digest, err := newDigest(c, githubClient, account)
	if err != nil {
		if gitHubError, ok := (err).(*github.ErrorResponse); ok {
			gitHubStatus := gitHubError.Response.StatusCode
			if gitHubStatus == http.StatusUnauthorized ||
				gitHubStatus == http.StatusForbidden {
				log.Errorf(c, "  GitHub auth error while getting digest, sending error email: %s", err.Error())
				var authErrorHtml bytes.Buffer
				if err := templates["github-auth-error-email"].Execute(&authErrorHtml, nil); err != nil {
					return false, err
				}

				digestMessage := &mail.Message{
					Sender:   "RetroGit <digests@retrogit.com>",
					To:       []string{emailAddress},
					Subject:  "RetroGit Digest Error",
					HTMLBody: authErrorHtml.String(),
				}
				err = mail.Send(c, digestMessage)
				return false, err
			}
		}
		return false, err
	}
	if digest.Empty() {
		return false, nil
	}

	var data = map[string]interface{}{
		"Digest": digest,
	}
	var digestHtml bytes.Buffer
	if err := templates["digest-email"].Execute(&digestHtml, data); err != nil {
		return false, err
	}

	digestMessage := &mail.Message{
		Sender:   "RetroGit <digests@retrogit.com>",
		To:       []string{emailAddress},
		Subject:  "RetroGit Digest",
		HTMLBody: digestHtml.String(),
	}
	err = mail.Send(c, digestMessage)
	return true, err
}

func githubOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) *AppError {
	code := r.FormValue("code")
	c := appengine.NewContext(r)
	token, err := githubOauthConfig.Exchange(c, code)
	if err != nil {
		return InternalError(err, "Could not exchange OAuth code")
	}

	githubClient := githubOAuthClient(c, *token)
	user, _, err := githubClient.Users.Get(c, "")
	if err != nil {
		return GitHubFetchError(err, "user")
	}

	account, err := getAccount(c, *user.ID)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return InternalError(err, "Could not look up user")
	}
	if account == nil {
		account = &Account{GitHubUserId: *user.ID}
	}
	account.OAuthToken = *token
	// Persist the default email address now, both to avoid additional lookups
	// later and to have a way to contact the user if they ever revoke their
	// OAuth token.
	emailAddress, err := account.GetDigestEmailAddress(c, githubClient)
	if err == nil && len(emailAddress) > 0 {
		account.DigestEmailAddress = emailAddress
	}
	err = account.Put(c)
	if err != nil {
		return InternalError(err, "Could not save user")
	}

	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	session.Values[sessionConfig.UserIdKey] = user.ID
	session.Save(r, w)
	continueUrl := r.FormValue("continue_url")
	if continueUrl != "" {
		continueUrlParsed, err := url.Parse(continueUrl)
		if err != nil || continueUrlParsed.Host != r.URL.Host {
			continueUrl = ""
		}
	}
	if continueUrl == "" {
		indexUrl, _ := router.Get("index").URL()
		continueUrl = indexUrl.String()
	}
	return RedirectToUrl(continueUrl)
}

func settingsHandler(w http.ResponseWriter, r *http.Request, state *AppSignedInState) *AppError {
	c := appengine.NewContext(r)
	user, _, err := state.GitHubClient.Users.Get(c, "")
	if err != nil {
		return GitHubFetchError(err, "user")
	}

	repos, err := getRepos(c, state.GitHubClient, state.Account, user)
	if err != nil {
		return GitHubFetchError(err, "repositories")
	}

	emails, _, err := state.GitHubClient.Users.ListEmails(c, nil)
	if err != nil {
		return GitHubFetchError(err, "emails")
	}
	emailAddresses := make([]string, len(emails))
	for i := range emails {
		emailAddresses[i] = *emails[i].Email
	}
	accountEmailAddress, err := state.Account.GetDigestEmailAddress(c, state.GitHubClient)
	if err != nil {
		return GitHubFetchError(err, "emails")
	}

	var data = map[string]interface{}{
		"Account":             state.Account,
		"User":                user,
		"Timezones":           timezones,
		"Repos":               repos,
		"EmailAddresses":      emailAddresses,
		"AccountEmailAddress": accountEmailAddress,
	}
	return templates["settings"].Render(w, data, state)
}

func saveSettingsHandler(w http.ResponseWriter, r *http.Request, state *AppSignedInState) *AppError {
	c := appengine.NewContext(r)
	account := state.Account

	user, _, err := state.GitHubClient.Users.Get(c, "")
	if err != nil {
		return GitHubFetchError(err, "user")
	}

	repos, err := getRepos(c, state.GitHubClient, account, user)
	if err != nil {
		return GitHubFetchError(err, "repos")
	}

	account.Frequency = r.FormValue("frequency")
	weeklyDay, err := strconv.Atoi(r.FormValue("weekly_day"))
	if err != nil {
		return BadRequest(err, "Malformed weekly_day value")
	}
	account.WeeklyDay = time.Weekday(weeklyDay)

	timezoneName := r.FormValue("timezone_name")
	_, err = time.LoadLocation(timezoneName)
	if err != nil {
		return BadRequest(err, "Malformed timezone_name value")
	}
	account.TimezoneName = timezoneName

	account.ExcludedRepoIds = make([]int64, 0)
	for _, repo := range repos.AllRepos {
		repoId := *repo.ID
		_, included := r.Form[fmt.Sprintf("repo-%d", repoId)]
		if !included {
			account.ExcludedRepoIds = append(account.ExcludedRepoIds, repoId)
		}
	}

	account.DigestEmailAddress = r.FormValue("email_address")

	err = account.Put(c)
	if err != nil {
		return InternalError(err, "Could not save user")
	}

	state.AddFlash("Settings saved.")
	return RedirectToRoute("settings")
}

func setInitialTimezoneHandler(w http.ResponseWriter, r *http.Request, state *AppSignedInState) *AppError {
	c := appengine.NewContext(r)
	account := state.Account

	timezoneName := r.FormValue("timezone_name")
	_, err := time.LoadLocation(timezoneName)
	if err != nil {
		return BadRequest(err, "Malformed timezone_name value")
	}
	account.TimezoneName = timezoneName

	err = account.Put(c)
	if err != nil {
		return InternalError(err, "Could not save user")
	}

	// Since we've now computed an initial timezone for the user, start a
	// background task to compute their digest. This ensures that we have most
	// of the relevant data already cached if they choose to view or email their
	// digest immediately.
	cacheDigestForAccountFunc.Call(c, account.GitHubUserId)

	return nil
}

var cacheDigestForAccountFunc = delay.Func(
	"cacheDigestForAccount",
	func(c context.Context, githubUserId int64) error {
		log.Infof(c, "Caching digest for %d...", githubUserId)
		account, err := getAccount(c, githubUserId)
		if err != nil {
			log.Errorf(c, "  Error looking up account: %s", err.Error())
			// Not returning error since we don't want these tasks to be
			// retried.
			return nil
		}

		githubClient := githubOAuthClient(c, account.OAuthToken)
		_, err = newDigest(c, githubClient, account)
		if err != nil {
			log.Errorf(c, "  Error computing digest: %s", err.Error())
		}
		log.Infof(c, "  Done!")
		return nil
	})

func deleteAccountHandler(w http.ResponseWriter, r *http.Request, state *AppSignedInState) *AppError {
	c := appengine.NewContext(r)
	state.Account.Delete(c)
	state.ClearSession()
	return RedirectToRoute("index")
}

func githubOAuthClient(c context.Context, token oauth2.Token) *github.Client {
	ctx_with_timeout, _ := context.WithTimeout(c, time.Second*60)
	appengineTransport := &urlfetch.Transport{Context: ctx_with_timeout}
	cachingTransport := &CachingTransport{
		Transport: appengineTransport,
		Context:   ctx_with_timeout,
	}

	tokenSource := githubOauthConfig.TokenSource(ctx_with_timeout, &token)
	httpClient := &http.Client{
		Transport: &oauth2.Transport{
			Base:   cachingTransport,
			Source: oauth2.ReuseTokenSource(nil, tokenSource),
		},
	}

	return github.NewClient(httpClient)
}
