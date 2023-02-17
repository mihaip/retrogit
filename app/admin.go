package main

import (
	"net/http"
	"sort"
	"strconv"

	"google.golang.org/appengine/v2"

	"github.com/google/go-github/github"
)

type AdminUserData struct {
	Account      *Account
	User         *github.User
	EmailAddress string
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
			githubClient := githubOAuthClient(c, account.OAuthToken)

			user, _, err := githubClient.Users.Get(c, "")

			emailAddress, err := account.GetDigestEmailAddress(c, githubClient)
			if err != nil {
				emailAddress = err.Error()
			}

			ch <- &AdminUserData{
				Account:      account,
				User:         user,
				EmailAddress: emailAddress,
			}
		}(&accounts[i])
	}

	users := make([]*AdminUserData, 0)
	for _ = range accounts {
		select {
		case r := <-ch:
			users = append(users, r)
		}
	}
	sort.Sort(AdminUserDataByGitHubUserId(users))

	var data = map[string]interface{}{
		"Users": users,
	}
	return templates["users-admin"].Render(w, data)
}

func digestAdminHandler(w http.ResponseWriter, r *http.Request) *AppError {
	userId, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
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

	githubClient := githubOAuthClient(c, account.OAuthToken)

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

func reposAdminHandler(w http.ResponseWriter, r *http.Request) *AppError {
	userId, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
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

	githubClient := githubOAuthClient(c, account.OAuthToken)

	user, _, err := githubClient.Users.Get(c, "")
	repos, reposErr := getRepos(c, githubClient, account, user)
	if err == nil {
		repos.Redact()
	}

	var data = map[string]interface{}{
		"User":       user,
		"Repos":      repos,
		"ReposError": reposErr,
	}
	return templates["repos-admin"].Render(w, data)
}

func deleteAccountAdminHandler(w http.ResponseWriter, r *http.Request) *AppError {
	userId, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
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
