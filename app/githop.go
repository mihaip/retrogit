package githop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"appengine"
	"appengine/delay"
	"appengine/mail"
	"appengine/urlfetch"

	"code.google.com/p/goauth2/oauth"
	"github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var router *mux.Router
var githubOauthConfig oauth.Config
var githubOauthPublicConfig oauth.Config
var timezones Timezones
var sessionStore *sessions.CookieStore
var sessionConfig SessionConfig
var templates map[string]*template.Template

func init() {
	initTemplates()
	timezones = initTimezones()
	sessionStore, sessionConfig = initSession()
	githubOauthConfig = initGithubOAuthConfig(true)
	githubOauthPublicConfig = initGithubOAuthConfig(false)

	router = mux.NewRouter()
	router.HandleFunc("/", indexHandler).Name("index")

	router.HandleFunc("/session/sign-in", signInHandler).Name("sign-in").Methods("POST")
	router.HandleFunc("/session/sign-out", signOutHandler).Name("sign-out").Methods("POST")
	router.HandleFunc("/github/callback", githubOAuthCallbackHandler)

	router.HandleFunc("/digest/view", viewDigestHandler).Name("view-digest")
	router.HandleFunc("/digest/send", sendDigestHandler).Name("send-digest").Methods("POST")
	router.HandleFunc("/digest/cron", digestCronHandler)

	router.HandleFunc("/account/settings", settingsHandler).Name("settings").Methods("GET")
	router.HandleFunc("/account/settings", saveSettingsHandler).Name("save-settings").Methods("POST")
	router.HandleFunc("/account/set-initial-timezone", setInitialTimezoneHandler).Name("set-initial-timezone").Methods("POST")
	router.HandleFunc("/account/delete", deleteAccountHandler).Name("delete-account").Methods("POST")

	router.HandleFunc("/admin/digest", digestAdminHandler)
	http.Handle("/", router)
}

func initGithubOAuthConfig(includePrivateRepos bool) (config oauth.Config) {
	path := "config/github-oauth"
	if appengine.IsDevAppServer() {
		path += "-dev"
	}
	path += ".json"
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panicf("Could not read GitHub OAuth config from %s: %s", path, err.Error())
	}
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Panicf("Could not parse GitHub OAuth config %s: %s", configBytes, err.Error())
	}
	repoScopeModifier := ""
	if !includePrivateRepos {
		repoScopeModifier = "public_"
	}
	config.Scope = fmt.Sprintf("%srepo user:email", repoScopeModifier)
	config.AuthURL = "https://github.com/login/oauth/authorize"
	config.TokenURL = "https://github.com/login/oauth/access_token"
	return
}

func initTemplates() {
	styles := loadStyles()
	funcMap := template.FuncMap{
		"routeUrl": func(name string) (string, error) {
			url, err := router.Get(name).URL()
			if err != nil {
				return "", err
			}
			return url.String(), nil
		},
		"style": func(names ...string) (result template.CSS) {
			for _, name := range names {
				result += styles[name]
			}
			return
		},
	}
	sharedFileNames, err := filepath.Glob("templates/shared/*.html")
	if err != nil {
		log.Panicf("Could not read shared template file names %s", err.Error())
	}
	templateFileNames, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Panicf("Could not read template file names %s", err.Error())
	}
	templates = make(map[string]*template.Template)
	for _, templateFileName := range templateFileNames {
		templateName := filepath.Base(templateFileName)
		templateName = strings.TrimSuffix(templateName, filepath.Ext(templateName))
		fileNames := make([]string, 0, len(sharedFileNames)+2)
		// The base template has to come first, except for the email template, which
		// doesn't use it
		if templateName != "digest-email" {
			fileNames = append(fileNames, "templates/base/page.html")
		}
		fileNames = append(fileNames, templateFileName)
		fileNames = append(fileNames, sharedFileNames...)
		_, templateFileName = filepath.Split(fileNames[0])
		templates[templateName], err = template.New(templateFileName).Funcs(funcMap).ParseFiles(fileNames...)
		if err != nil {
			log.Panicf("Could not parse template files for %s: %s", templateFileName, err.Error())
		}
	}
}

func loadStyles() (result map[string]template.CSS) {
	stylesBytes, err := ioutil.ReadFile("config/styles.json")
	if err != nil {
		log.Panicf("Could not read styles JSON: %s", err.Error())
	}
	var stylesJson interface{}
	err = json.Unmarshal(stylesBytes, &stylesJson)
	if err != nil {
		log.Panicf("Could not parse styles JSON %s: %s", stylesBytes, err.Error())
	}
	result = make(map[string]template.CSS)
	var parse func(string, map[string]interface{}, *string)
	parse = func(path string, stylesJson map[string]interface{}, currentStyle *string) {
		if path != "" {
			path += "."
		}
		for k, v := range stylesJson {
			switch v.(type) {
			case string:
				*currentStyle += k + ":" + v.(string) + ";"
			case map[string]interface{}:
				nestedStyle := ""
				parse(path+k, v.(map[string]interface{}), &nestedStyle)
				result[path+k] = template.CSS(nestedStyle)
			default:
				log.Panicf("Unexpected type for %s in styles JSON", k)
			}
		}
	}
	parse("", stylesJson.(map[string]interface{}), nil)
	return
}

func signInHandler(w http.ResponseWriter, r *http.Request) {
	config := &githubOauthConfig
	if r.FormValue("include_private") != "1" {
		config = &githubOauthPublicConfig
	}
	http.Redirect(w, r, config.AuthCodeURL(""), http.StatusFound)
}

func signOutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	session.Options.MaxAge = -1
	session.Save(r, w)
	indexUrl, _ := router.Get("index").URL()
	http.Redirect(w, r, indexUrl.String(), http.StatusFound)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId, ok := session.Values[sessionConfig.UserIdKey].(int)
	if !ok {
		if err := templates["index-signed-out"].Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if account == nil {
		// Can't look up the account, session cookie must be invalid, clear it.
		indexUrl, _ := router.Get("sign-out").URL()
		http.Redirect(w, r, indexUrl.String(), http.StatusFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	var wg sync.WaitGroup
	wg.Add(2)
	var user *github.User
	var userErr error
	var emailAddress string
	var emailAddressErr error
	go func() {
		user, _, userErr = githubClient.Users.Get("")
		wg.Done()
	}()
	go func() {
		emailAddress, emailAddressErr = account.GetDigestEmailAddress(githubClient)
		wg.Done()
	}()
	wg.Wait()
	if userErr != nil {
		http.Error(w, userErr.Error(), http.StatusInternalServerError)
		return
	}
	if emailAddressErr != nil {
		http.Error(w, emailAddressErr.Error(), http.StatusInternalServerError)
		return
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
	flashes := session.Flashes()
	if len(flashes) > 0 {
		session.Save(r, w)
	}
	var data = map[string]interface{}{
		"User":            user,
		"SettingsSummary": settingsSummary,
		"DetectTimezone":  !account.HasTimezoneSet,
		"Flashes":         flashes,
	}
	if err := templates["index"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func viewDigestHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId := session.Values[sessionConfig.UserIdKey].(int)
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	digest, err := newDigest(c, githubClient, account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	var data = map[string]interface{}{
		"Digest": digest,
	}
	if err := templates["digest-page"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func sendDigestHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId := session.Values[sessionConfig.UserIdKey].(int)
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = sendDigestForAccount(account, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.AddFlash("Digest emailed!")
	session.Save(r, w)
	indexUrl, _ := router.Get("index").URL()
	http.Redirect(w, r, indexUrl.String(), http.StatusFound)
}

func digestCronHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	accounts, err := getAllAccounts(c)
	if err != nil {
		c.Errorf("Error looking up accounts: %s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, account := range accounts {
		if account.Frequency == "weekly" {
			now := time.Now().In(account.TimezoneLocation)
			if now.Weekday() != account.WeeklyDay {
				c.Infof("Skipping %d, since it wants weekly digests on %ss and today is a %s.",
					account.GitHubUserId, account.WeeklyDay, now.Weekday())
				continue
			}
		}
		c.Infof("Enqueing task for %d...", account.GitHubUserId)
		sendDigestForAccountFunc.Call(c, account.GitHubUserId)
	}
	fmt.Fprint(w, "Done")
}

var sendDigestForAccountFunc = delay.Func(
	"sendDigestForAccount",
	func(c appengine.Context, githubUserId int) error {
		c.Infof("Sending digest for %d...", githubUserId)
		account, err := getAccount(c, githubUserId)
		if err != nil {
			c.Errorf("  Error looking up account: %s", err.Error())
			return err
		}
		sent, err := sendDigestForAccount(account, c)
		if err != nil {
			c.Errorf("  Error: %s", err.Error())
		} else if sent {
			c.Infof("  Sent!")
		} else {
			c.Infof("  Not sent, digest was empty")
		}
		return err
	})

func sendDigestForAccount(account *Account, c appengine.Context) (bool, error) {
	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	digest, err := newDigest(c, githubClient, account)
	if err != nil {
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

	emailAddress, err := account.GetDigestEmailAddress(githubClient)
	if err != nil {
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

func githubOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	c := appengine.NewContext(r)
	oauthTransport := githubOAuthTransport(c)
	token, err := oauthTransport.Exchange(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oauthTransport.Token = token
	githubClient := github.NewClient(oauthTransport.Client())
	user, _, err := githubClient.Users.Get("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	account := &Account{
		GitHubUserId: *user.ID,
		OAuthToken:   *token,
	}
	err = account.Put(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	session.Values[sessionConfig.UserIdKey] = user.ID
	session.Save(r, w)
	indexUrl, _ := router.Get("index").URL()
	http.Redirect(w, r, indexUrl.String(), http.StatusFound)
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId := session.Values[sessionConfig.UserIdKey].(int)
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	user, _, err := githubClient.Users.Get("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	repos, err := getRepos(c, githubClient, account, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	emails, _, err := githubClient.Users.ListEmails(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	emailAddresses := make([]string, len(emails))
	for i := range emails {
		emailAddresses[i] = *emails[i].Email
	}
	accountEmailAddress, err := account.GetDigestEmailAddress(githubClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var data = map[string]interface{}{
		"Account":             account,
		"User":                user,
		"Timezones":           timezones,
		"Repos":               repos,
		"EmailAddresses":      emailAddresses,
		"AccountEmailAddress": accountEmailAddress,
	}
	if err := templates["settings"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func saveSettingsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId := session.Values[sessionConfig.UserIdKey].(int)
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	user, _, err := githubClient.Users.Get("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	repos, err := getRepos(c, githubClient, account, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	account.Frequency = r.FormValue("frequency")
	weeklyDay, err := strconv.Atoi(r.FormValue("weekly_day"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	account.WeeklyDay = time.Weekday(weeklyDay)

	timezoneName := r.FormValue("timezone_name")
	_, err = time.LoadLocation(timezoneName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	account.TimezoneName = timezoneName

	account.ExcludedRepoIds = make([]int, 0)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	settingsUrl, _ := router.Get("settings").URL()
	http.Redirect(w, r, settingsUrl.String(), http.StatusFound)
}

func setInitialTimezoneHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId := session.Values[sessionConfig.UserIdKey].(int)
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	timezoneName := r.FormValue("timezone_name")
	_, err = time.LoadLocation(timezoneName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	account.TimezoneName = timezoneName

	err = account.Put(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Since we've now computed an initial timezone for the user, start a
	// background task to compute their digest. This ensures that we have most
	// of the relevant data already cached if they choose to view or email their
	// digest immediately.
	cacheDigestForAccountFunc.Call(c, account.GitHubUserId)
}

var cacheDigestForAccountFunc = delay.Func(
	"cacheDigestForAccount",
	func(c appengine.Context, githubUserId int) error {
		c.Infof("Caching digest for %d...", githubUserId)
		account, err := getAccount(c, githubUserId)
		if err != nil {
			c.Errorf("  Error looking up account: %s", err.Error())
			// Not returning error since we don't want these tasks to be
			// retried.
			return nil
		}

		oauthTransport := githubOAuthTransport(c)
		oauthTransport.Token = &account.OAuthToken
		githubClient := github.NewClient(oauthTransport.Client())
		_, err = newDigest(c, githubClient, account)
		if err != nil {
			c.Errorf("  Error computing digest: %s", err.Error())
		}
		c.Infof("  Done!")
		return nil
	})

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId := session.Values[sessionConfig.UserIdKey].(int)
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	account.Delete(c)
	session.Options.MaxAge = -1
	session.Save(r, w)

	indexUrl, _ := router.Get("index").URL()
	http.Redirect(w, r, indexUrl.String(), http.StatusFound)
}

func digestAdminHandler(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.Atoi(r.FormValue("user_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if account == nil {
		http.Error(w, "Couldn't find account", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	digest, err := newDigest(c, githubClient, account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	var data = map[string]interface{}{
		"Digest": digest,
	}
	if err := templates["digest-admin"].Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func githubOAuthTransport(c appengine.Context) *oauth.Transport {
	appengineTransport := &urlfetch.Transport{Context: c}
	appengineTransport.Deadline = time.Second * 60
	cachingTransport := &CachingTransport{
		Transport: appengineTransport,
		Context:   c,
	}
	return &oauth.Transport{
		Config:    &githubOauthConfig,
		Transport: cachingTransport,
	}
}
