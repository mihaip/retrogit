package githop

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"appengine"
	"appengine/urlfetch"

	"code.google.com/p/goauth2/oauth"
	"github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var router *mux.Router
var githubOauthConfig oauth.Config
var sessionStore *sessions.CookieStore
var sessionConfig SessionConfig

func initGithubOAuthConfig() {
	path := "config/github-oauth"
	if appengine.IsDevAppServer() {
		path += "-dev"
	}
	path += ".json"
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panicf("Could not read GitHub OAuth config from %s: %s", path, err.Error())
	}
	err = json.Unmarshal(configBytes, &githubOauthConfig)
	if err != nil {
		log.Panicf("Could not parse GitHub OAuth config %s: %s", configBytes, err.Error())
	}
	githubOauthConfig.Scope = "repo"
	githubOauthConfig.AuthURL = "https://github.com/login/oauth/authorize"
	githubOauthConfig.TokenURL = "https://github.com/login/oauth/access_token"
}

func init() {
	sessionStore, sessionConfig = initSession()
	initGithubOAuthConfig()

	router = mux.NewRouter()
	router.HandleFunc("/", indexHandler).Name("index")
	router.HandleFunc("/session/sign-in", signInHandler).Name("sign-in")
	router.HandleFunc("/session/sign-out", signOutHandler).Name("sign-out")
	router.HandleFunc("/github/callback", githubOAuthCallbackHandler)
	http.Handle("/", router)
}

var indexTemplate = template.Must(template.ParseFiles("templates/index.html"))
var indexSignedOutTemplate = template.Must(template.ParseFiles("templates/index-signed-out.html"))

func signInHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, githubOauthConfig.AuthCodeURL(""), http.StatusFound)
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
		signInUrl, _ := router.Get("sign-in").URL()
		var data = map[string]string{
			"SignInUrl": signInUrl.String(),
		}
		if err := indexSignedOutTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	account, err := GetAccount(appengine.NewContext(r), userId)
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

	oauthTransport := githubOAuthTransport(r)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	user, _, err := githubClient.Users.Get("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The username parameter must be left blank so that we can get all of the
	// repositories the user has access to, not just ones that they own.
	repos, _, err := githubClient.Repositories.List("", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	orgs, _, err := githubClient.Organizations.List("", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, org := range orgs {
		orgRepos, _, err := githubClient.Repositories.ListByOrg(*org.Login, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		newRepos := make([]github.Repository, len(repos)+len(orgRepos))
		copy(newRepos, repos)
		copy(newRepos[len(repos):], orgRepos)
		repos = newRepos
	}

	now := time.Now()
	digestStartTime := time.Date(now.Year()-1, now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	digestEndTime := digestStartTime.AddDate(0, 0, 7)

	// Only look at repos that may have activity in the digest interval.
	var digestRepos []github.Repository
	for _, repo := range repos {
		if repo.CreatedAt.Before(digestEndTime) && repo.PushedAt.After(digestStartTime) {
			digestRepos = append(digestRepos, repo)
		}
	}
	repos = digestRepos
	digest := Digest{
		User:        user,
		RepoDigests: make([]*RepoDigest, 0, len(repos)),
		StartTime:   digestStartTime,
		EndTime:     digestEndTime,
	}
	err = digest.Fetch(repos, githubClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	signOutUrl, _ := router.Get("sign-out").URL()
	var data = map[string]interface{}{
		"SignOutUrl": signOutUrl.String(),
		"Digest":     digest,
	}
	if err := indexTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func githubOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	oauthTransport := githubOAuthTransport(r)
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
	err = account.Put(appengine.NewContext(r))
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

func githubOAuthTransport(r *http.Request) *oauth.Transport {
	appengineContext := appengine.NewContext(r)
	appengineTransport := &urlfetch.Transport{Context: appengineContext}
	cachingTransport := &CachingTransport{
		Transport: appengineTransport,
		Context:   appengineContext,
	}
	return &oauth.Transport{
		Config:    &githubOauthConfig,
		Transport: cachingTransport,
	}
}
