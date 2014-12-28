package retrogit

import (
	"net/http"
	"sort"
	"strconv"

	"appengine"

	"github.com/google/go-github/github"
)

type AdminUserData struct {
	Account      *Account
	User         *github.User
	EmailAddress string
	Repos        *Repos
	ReposError   error
}

// sort.Interface implementation for sorting AdminUserDatas
type AdminUserDataByGitHubUserId []*AdminUserData

func (a AdminUserDataByGitHubUserId) Len() int      { return len(a) }
func (a AdminUserDataByGitHubUserId) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a AdminUserDataByGitHubUserId) Less(i, j int) bool {
	return a[i].Account.GitHubUserId < a[j].Account.GitHubUserId
}

func usersAdminHandler(w http.ResponseWriter, r *http.Request) *AppError {
	c := appengine.NewContext(r)
	accounts, err := getAllAccounts(c)
	if err != nil {
		return InternalError(err, "Could not look up accounts")
	}

	ch := make(chan *AdminUserData)
	for i := range accounts {
		go func(account *Account) {
			oauthTransport := githubOAuthTransport(c)
			oauthTransport.Token = &account.OAuthToken
			githubClient := github.NewClient(oauthTransport.Client())

			user, _, err := githubClient.Users.Get("")

			emailAddress, err := account.GetDigestEmailAddress(githubClient)
			if err != nil {
				emailAddress = err.Error()
			}

			repos, reposErr := getRepos(c, githubClient, account, user)
			ch <- &AdminUserData{
				Account:      account,
				User:         user,
				EmailAddress: emailAddress,
				Repos:        repos,
				ReposError:   reposErr,
			}
		}(&accounts[i])
	}

	users := make([]*AdminUserData, 0)
	totalRepos := 0
	for _ = range accounts {
		select {
		case r := <-ch:
			users = append(users, r)
			if r.Repos != nil {
				totalRepos += len(r.Repos.AllRepos)
			}
		}
	}
	sort.Sort(AdminUserDataByGitHubUserId(users))

	var data = map[string]interface{}{
		"Users":      users,
		"TotalUsers": len(users),
		"TotalRepos": totalRepos,
	}
	return templates["users-admin"].Render(w, data)
}

func digestAdminHandler(w http.ResponseWriter, r *http.Request) *AppError {
	userId, err := strconv.Atoi(r.FormValue("user_id"))
	if err != nil {
		return BadRequest(err, "Malformed user_id value")
	}
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if account == nil {
		return BadRequest(err, "user_id does not point to an account")
	}
	if err != nil {
		return InternalError(err, "Could not look up account")
	}

	oauthTransport := githubOAuthTransport(c)
	oauthTransport.Token = &account.OAuthToken
	githubClient := github.NewClient(oauthTransport.Client())

	digest, err := newDigest(c, githubClient, account)
	if err != nil {
		return GitHubFetchError(err, "digest")
	}
	digest.Redact()
	var data = map[string]interface{}{
		"Digest": digest,
	}
	return templates["digest-admin"].Render(w, data)
}

func deleteAccountAdminHandler(w http.ResponseWriter, r *http.Request) *AppError {
	userId, err := strconv.Atoi(r.FormValue("user_id"))
	if err != nil {
		return BadRequest(err, "Malformed user_id value")
	}
	c := appengine.NewContext(r)
	account, err := getAccount(c, userId)
	if account == nil {
		return BadRequest(err, "user_id does not point to an account")
	}
	if err != nil {
		return InternalError(err, "Could not look up account")
	}

	account.Delete(c)
	return RedirectToRoute("users-admin")
}
