package retrogit

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"appengine"

	"github.com/google/go-github/github"
	"github.com/gorilla/sessions"
)

const (
	AppErrorTypeInternal = iota
	AppErrorTypeTemplate
	AppErrorTypeGitHubFetch
	AppErrorTypeRedirect
	AppErrorTypeBadInput
)

type AppError struct {
	Error   error
	Message string
	Code    int
	Type    int
}

type AppSignedInState struct {
	Account        *Account
	GitHubClient   *github.Client
	session        *sessions.Session
	request        *http.Request
	responseWriter http.ResponseWriter
}

func (state *AppSignedInState) AddFlash(value interface{}) {
	state.session.AddFlash(value)
	state.saveSession()
}

func (state *AppSignedInState) Flashes() []interface{} {
	flashes := state.session.Flashes()
	if len(flashes) > 0 {
		state.saveSession()
	}
	return flashes
}

func (state *AppSignedInState) ClearSession() {
	state.session.Options.MaxAge = -1
	state.saveSession()
}

func (state *AppSignedInState) saveSession() {
	state.session.Save(state.request, state.responseWriter)
}

func GitHubFetchError(err error, fetchType string) *AppError {
	return &AppError{
		Error:   err,
		Message: fmt.Sprintf("Could not fetch %s data from GitHub", fetchType),
		Code:    http.StatusInternalServerError,
		Type:    AppErrorTypeGitHubFetch,
	}
}

func InternalError(err error, message string) *AppError {
	return &AppError{
		Error:   err,
		Message: message,
		Code:    http.StatusInternalServerError,
		Type:    AppErrorTypeInternal,
	}
}

func RedirectToUrl(url string) *AppError {
	return &AppError{
		Error:   nil,
		Message: url,
		Code:    http.StatusFound,
		Type:    AppErrorTypeRedirect,
	}
}

func BadRequest(err error, message string) *AppError {
	return &AppError{
		Error:   err,
		Message: message,
		Code:    http.StatusBadRequest,
		Type:    AppErrorTypeBadInput,
	}
}

func RedirectToRoute(routeName string, queryParameters ...map[string]string) *AppError {
	route := router.Get(routeName)
	if route == nil {
		return InternalError(
			errors.New("No such route"),
			fmt.Sprintf("Could not look up route '%s'", routeName))
	}
	routeUrl, err := route.URL()
	if err != nil {
		return InternalError(
			errors.New("Could not get route URL"),
			fmt.Sprintf("Could not get route URL for route '%s'", routeName))
	}
	if len(queryParameters) != 0 {
		routeUrlQuery := routeUrl.Query()
		for k, v := range queryParameters[0] {
			routeUrlQuery.Set(k, v)
		}
		routeUrl.RawQuery = routeUrlQuery.Encode()
	}
	return RedirectToUrl(routeUrl.String())
}

func NotSignedIn(r *http.Request) *AppError {
	return RedirectToRoute("index", map[string]string{"continue_url": r.URL.String()})
}

func Panic(panicData interface{}) *AppError {
	return InternalError(
		errors.New(fmt.Sprintf("Panic: %+v\n\n%s", panicData, stack(3))),
		"Panic")
}

type AppHandler func(http.ResponseWriter, *http.Request) *AppError

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer panicRecovery(w, r)
	if e := fn(w, r); e != nil {
		handleAppError(e, w, r)
	}
}

type SignedInAppHandler func(http.ResponseWriter, *http.Request, *AppSignedInState) *AppError

func (fn SignedInAppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer panicRecovery(w, r)
	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	userId, ok := session.Values[sessionConfig.UserIdKey].(int)
	if !ok {
		handleAppError(NotSignedIn(r), w, r)
		return
	}
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if account == nil || err != nil {
		handleAppError(NotSignedIn(r), w, r)
		return
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	state := &AppSignedInState{
		Account:        account,
		GitHubClient:   githubClient,
		session:        session,
		responseWriter: w,
		request:        r,
	}

	if e := fn(w, r, state); e != nil {
		handleAppError(e, w, r)
	}
}

func panicRecovery(w http.ResponseWriter, r *http.Request) {
	if panicData := recover(); panicData != nil {
		handleAppError(Panic(panicData), w, r)
	}
}

func handleAppError(e *AppError, w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if e.Type == AppErrorTypeGitHubFetch {
		if gitHubError, ok := (e.Error).(*github.ErrorResponse); ok {
			gitHubStatus := gitHubError.Response.StatusCode
			if gitHubStatus == http.StatusUnauthorized ||
				gitHubStatus == http.StatusForbidden {
				var data = map[string]interface{}{
					"ContinueUrl": r.URL,
					"IsForbidden": gitHubStatus == http.StatusForbidden,
				}

				e = templates["github-auth-error"].Render(w, data)
				if e != nil {
					handleAppError(e, w, r)
				}
				return
			}
		} else {
			c.Errorf("GitHub fetch error was not of type github.ErrorResponse")
		}
	} else if e.Type == AppErrorTypeRedirect {
		http.Redirect(w, r, e.Message, e.Code)
		return
	}
	if e.Type != AppErrorTypeBadInput {
		c.Errorf("%v", e.Error)
	} else {
		c.Infof("%v", e.Error)
	}
	http.Error(w, e.Message, e.Code)
}

type Template struct {
	*template.Template
}

func (t *Template) Render(w io.Writer, data map[string]interface{}, state ...*AppSignedInState) *AppError {
	if len(state) > 0 {
		data["Flashes"] = state[0].Flashes()
	}
	err := t.Execute(w, data)
	if err != nil {
		return &AppError{
			Error:   err,
			Message: fmt.Sprintf("Could not render template '%s'", t.Name()),
			Code:    http.StatusInternalServerError,
			Type:    AppErrorTypeTemplate,
		}
	}
	return nil
}

func loadTemplates() (templates map[string]*Template) {
	styles := loadStyles()
	funcMap := template.FuncMap{
		"routeUrl": func(name string) (string, error) {
			url, err := router.Get(name).URL()
			if err != nil {
				return "", err
			}
			return url.String(), nil
		},
		"absoluteRouteUrl": func(name string) (string, error) {
			url, err := router.Get(name).URL()
			if err != nil {
				return "", err
			}
			var baseUrl string
			if appengine.IsDevAppServer() {
				baseUrl = "http://localhost:8080"
			} else {
				baseUrl = "https://www.retrogit.com"
			}
			return baseUrl + url.String(), nil
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
	templates = make(map[string]*Template)
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
		parsedTemplate, err := template.New(templateFileName).Funcs(funcMap).ParseFiles(fileNames...)
		if err != nil {
			log.Printf("Could not parse template files for %s: %s", templateFileName, err.Error())
		}
		templates[templateName] = &Template{parsedTemplate}
	}
	return templates
}

func loadStyles() (result map[string]template.CSS) {
	stylesBytes, err := ioutil.ReadFile("config/styles.json")
	if err != nil {
		log.Panicf("Could not read styles JSON: %s", err.Error())
	}
	var stylesJson interface{}
	err = json.Unmarshal(stylesBytes, &stylesJson)
	result = make(map[string]template.CSS)
	if err != nil {
		log.Printf("Could not parse styles JSON %s: %s", stylesBytes, err.Error())
		return
	}
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
				log.Printf("Unexpected type for %s in styles JSON, ignoring", k)
			}
		}
	}
	parse("", stylesJson.(map[string]interface{}), nil)
	return
}
