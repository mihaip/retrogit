package githop

import (
	"html/template"
	"net/http"
)

func init() {
	http.HandleFunc("/", index)
}

var indexTemplate = template.Must(template.ParseFiles("templates/index.html"))

func index(w http.ResponseWriter, r *http.Request) {
	tc := make(map[string]interface{})
	if err := indexTemplate.Execute(w, tc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
