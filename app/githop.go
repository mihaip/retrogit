package githop

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"appengine"
	"appengine/urlfetch"

	"code.google.com/p/goauth2/oauth"
	"github.com/google/go-github/github"
	"github.com/gorilla/mux"
)

var router *mux.Router
var githubOauthConfig oauth.Config

type RepositoryDigest struct {
	Repository *github.Repository
	Commits    []github.RepositoryCommit
}

type Digest struct {
	User              *github.User
	RepositoryDigests []RepositoryDigest
}

func initGithubOAuthConfig() {
	path := "config/github-oauth"
	if appengine.IsDevAppServer() {
		path += "-dev"
	}
	path += ".json"
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panicf("Could not read GitHut OAuth config from %s: %s", path, err.Error())
	}
	err = json.Unmarshal(configBytes, &githubOauthConfig)
	if err != nil {
		log.Panicf("Could not parse GitHut OAuth %s", err.Error())
	}
	githubOauthConfig.Scope = "repo"
	githubOauthConfig.AuthURL = "https://github.com/login/oauth/authorize"
	githubOauthConfig.TokenURL = "https://github.com/login/oauth/access_token"
}

func init() {
	initGithubOAuthConfig()

	router = mux.NewRouter()
	router.HandleFunc("/", indexHandler).Name("index")
	router.HandleFunc("/github/callback", githubOAuthCallbackHandler)
	http.Handle("/", router)
}

var indexTemplate = template.Must(template.ParseFiles("templates/index.html"))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tokenEncoded := r.FormValue("token")
	if tokenEncoded == "" {
		http.Redirect(w, r, githubOauthConfig.AuthCodeURL(""), http.StatusFound)
		return
	}
	tokenBytes, err := base64.URLEncoding.DecodeString(tokenEncoded)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var token oauth.Token
	err = json.Unmarshal(tokenBytes, &token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	appengineContext := appengine.NewContext(r)
	oauthTransport := &oauth.Transport{
		Config:    &githubOauthConfig,
		Transport: &urlfetch.Transport{Context: appengineContext},
		Token:     &token,
	}
	githubClient := github.NewClient(oauthTransport.Client())

	user, _, err := githubClient.Users.Get("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	now := time.Now()
	digestStartTime := time.Date(now.Year()-1, now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	digestEndTime := digestStartTime.AddDate(0, 0, 7)

	repos, _, err := githubClient.Repositories.List(*user.Login, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	digest := Digest{User: user, RepositoryDigests: make([]RepositoryDigest, 0, len(repos))}
	for i, repo := range repos {
		commits, _, err := githubClient.Repositories.ListCommits(
			*repo.Owner.Login,
			*repo.Name,
			&github.CommitsListOptions{
				Author: *user.Login,
				Since:  digestStartTime,
				Until:  digestEndTime,
			})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(commits) > 0 {
			n := len(digest.RepositoryDigests)
			digest.RepositoryDigests = digest.RepositoryDigests[0 : n+1]
			digest.RepositoryDigests[n] = RepositoryDigest{&repos[i], commits}
		}
	}

	if err := indexTemplate.Execute(w, digest); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func githubOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	appengineContext := appengine.NewContext(r)
	oauthTransport := &oauth.Transport{
		Config:    &githubOauthConfig,
		Transport: &urlfetch.Transport{Context: appengineContext},
	}
	token, err := oauthTransport.Exchange(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tokenBytes, err := json.Marshal(token)
	tokenEncoded := base64.StdEncoding.EncodeToString(tokenBytes)
	redirectUrl, err := router.GetRoute("index").URL()
	redirectParams := url.Values{}
	redirectParams.Add("token", tokenEncoded)
	redirectUrl.RawQuery = redirectParams.Encode()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectUrl.String(), http.StatusFound)
}
