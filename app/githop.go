package githop

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"

	"appengine"
	"appengine/urlfetch"

	"code.google.com/p/goauth2/oauth"
	"github.com/google/go-github/github"
)

func init() {
	http.HandleFunc("/", index)
}

var indexTemplate = template.Must(template.ParseFiles("templates/index.html"))

func index(w http.ResponseWriter, r *http.Request) {
	// TODO: Don't do this every request
	github_oauth_config_path := "config/github-oauth"
	if appengine.IsDevAppServer() {
		github_oauth_config_path += "-dev"
	}
	github_oauth_config_path += ".json"
	github_oauth_config_bytes, err := ioutil.ReadFile(github_oauth_config_path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var github_oauth_config oauth.Config
	err = json.Unmarshal(github_oauth_config_bytes, &github_oauth_config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	github_oauth_config.Scope = "repo"
	github_oauth_config.AuthURL = "https://github.com/login/oauth/authorize"
	github_oauth_config.TokenURL = "https://github.com/login/oauth/access_token"

	code := r.FormValue("code")
	if code == "" {
		http.Redirect(w, r, github_oauth_config.AuthCodeURL(""), http.StatusFound)
		return
	}
	appengine_context := appengine.NewContext(r)
	oauth_transport := &oauth.Transport{
		Config:    &github_oauth_config,
		Transport: &urlfetch.Transport{Context: appengine_context},
	}
	token, _ := oauth_transport.Exchange(code)
	oauth_transport.Token = token

	gitub_client := github.NewClient(oauth_transport.Client())
	repos, _, err := gitub_client.Repositories.List("", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := indexTemplate.Execute(w, repos); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
