package githop

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"

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

var templates = template.Must(template.ParseGlob("templates/*.html"))

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
		if err := templates.ExecuteTemplate(w, "index-signed-out", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	account, err := getAccount(appengine.NewContext(r), userId)
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

	digest, err := newDigest(githubClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	signOutUrl, _ := router.Get("sign-out").URL()
	var data = map[string]interface{}{
		"SignOutUrl": signOutUrl.String(),
		"Digest":     digest,
	}
	if err := templates.ExecuteTemplate(w, "index", data); err != nil {
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
	err = account.put(appengine.NewContext(r))
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
