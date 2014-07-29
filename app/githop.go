package githop

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"time"

	"appengine"
	"appengine/memcache"
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

type SessionConfig struct {
	AuthenticationKey string
	EncryptionKey     string
	CookieName        string
	TokenKey          string
}

type RepoDigest struct {
	Repo    *github.Repository
	Commits []github.RepositoryCommit
}

// sort.Interface implementation for sorting RepoDigests.
type ByRepoFullName []*RepoDigest

func (a ByRepoFullName) Len() int           { return len(a) }
func (a ByRepoFullName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRepoFullName) Less(i, j int) bool { return *a[i].Repo.FullName < *a[j].Repo.FullName }

type Digest struct {
	User        *github.User
	StartTime   time.Time
	EndTime     time.Time
	RepoDigests []*RepoDigest
}

func (digest *Digest) Fetch(repos []github.Repository, githubClient *github.Client) error {
	type RepoDigestResponse struct {
		repoDigest *RepoDigest
		err        error
	}
	ch := make(chan *RepoDigestResponse)
	for _, repo := range repos {
		go func(repo github.Repository) {
			commits, _, err := githubClient.Repositories.ListCommits(
				*repo.Owner.Login,
				*repo.Name,
				&github.CommitsListOptions{
					Author: *digest.User.Login,
					Since:  digest.StartTime,
					Until:  digest.EndTime,
				})
			if err != nil {
				ch <- &RepoDigestResponse{nil, err}
			} else {
				ch <- &RepoDigestResponse{&RepoDigest{&repo, commits}, nil}
			}
		}(repo)
	}
	for i := 0; i < len(repos); i++ {
		select {
		case r := <-ch:
			if r.err != nil {
				return r.err
			}
			digest.RepoDigests = append(digest.RepoDigests, r.repoDigest)
		}
	}
	sort.Sort(ByRepoFullName(digest.RepoDigests))
	return nil
}

func initSessionConfig() {
	configBytes, err := ioutil.ReadFile("config/session.json")
	if err != nil {
		log.Panicf("Could not read session config: %s", err.Error())
	}
	err = json.Unmarshal(configBytes, &sessionConfig)
	if err != nil {
		log.Panicf("Could not parse session config %s: %s", configBytes, err.Error())
	}

	authenticationKey, err := base64.StdEncoding.DecodeString(sessionConfig.AuthenticationKey)
	if err != nil {
		log.Panicf("Could not decode session config authentication key %s: %s", sessionConfig.AuthenticationKey, err.Error())
	}
	encryptionKey, err := base64.StdEncoding.DecodeString(sessionConfig.EncryptionKey)
	if err != nil {
		log.Panicf("Could not decode session config encryption key %s: %s", sessionConfig.EncryptionKey, err.Error())
	}

	sessionStore = sessions.NewCookieStore(authenticationKey, encryptionKey)
	sessionStore.Options.Path = "/"
	sessionStore.Options.MaxAge = 86400 * 30
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = !appengine.IsDevAppServer()
}

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
	initSessionConfig()
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
	tokenEncoded, ok := session.Values[sessionConfig.TokenKey].(string)
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
	token, err := decodeOAuthToken(tokenEncoded)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	oauthTransport := githubOAuthTransport(r)
	oauthTransport.Token = token
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
	tokenEncoded, err := encodeOAuthToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := sessionStore.Get(r, sessionConfig.CookieName)
	session.Values[sessionConfig.TokenKey] = tokenEncoded
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

func encodeOAuthToken(token *oauth.Token) (string, error) {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

func decodeOAuthToken(tokenEncoded string) (*oauth.Token, error) {
	tokenBytes, err := base64.URLEncoding.DecodeString(tokenEncoded)
	if err != nil {
		return nil, err
	}
	var token oauth.Token
	err = json.Unmarshal(tokenBytes, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// Simple http.RoundTripper implementation which wraps an existing transport and
// caches all responses for GET and HEAD requests. Meant to speed up the
// iteration cycle during development.
type CachingTransport struct {
	Transport http.RoundTripper
	Context   appengine.Context
}

func (t *CachingTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.Method != "GET" && req.Method != "HEAD" {
		return t.Transport.RoundTrip(req)
	}
	cacheKey := "CachingTransport:" + req.URL.String() + "#"
	authorizationHeaders, ok := req.Header["Authorization"]
	if ok {
		cacheKey += strings.Join(authorizationHeaders, "#")
	} else {
		cacheKey += "Unauthorized"
	}

	cachedRespItem, err := memcache.Get(t.Context, cacheKey)
	if err != nil && err != memcache.ErrCacheMiss {
		t.Context.Errorf("Error getting cached response: %v", err)
		return t.Transport.RoundTrip(req)
	}
	if err == nil {
		cacheRespBuffer := bytes.NewBuffer(cachedRespItem.Value)
		resp, err := http.ReadResponse(bufio.NewReader(cacheRespBuffer), req)
		if err == nil {
			return resp, nil
		} else {
			t.Context.Errorf("Error readings bytes for cached response: %v", err)
		}
	}
	resp, err = t.Transport.RoundTrip(req)
	if err != nil {
		return
	}
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Context.Errorf("Error dumping bytes for cached response: %v", err)
		return resp, nil
	}
	err = memcache.Set(t.Context, &memcache.Item{Key: cacheKey, Value: respBytes})
	if err != nil {
		t.Context.Errorf("Error setting cached response: %v", err)
	}
	return resp, nil
}
