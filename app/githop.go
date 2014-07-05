package githop

import (
	"github.com/google/go-github/github"
	"html/template"
	"net/http"

	"appengine"
    "appengine/urlfetch"
)

func init() {
	http.HandleFunc("/", index)
}

var indexTemplate = template.Must(template.ParseFiles("templates/index.html"))

func index(w http.ResponseWriter, r *http.Request) {
	appengine_context := appengine.NewContext(r)
	http_client := urlfetch.Client(appengine_context)

	gitub_client := github.NewClient(http_client)
	orgs, _, err := gitub_client.Organizations.List("mihaip", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := indexTemplate.Execute(w, orgs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
