package githop

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"appengine"
	"appengine/datastore"

	"code.google.com/p/goauth2/oauth"
	"github.com/google/go-github/github"
)

type Account struct {
	GitHubUserId int `datastore:",noindex"`
	// The datastore API doesn't store maps, and the token contains one. We
	// thefore store a gob-serialized version instead.
	OAuthTokenSerialized []byte
	OAuthToken           oauth.Token    `datastore:"-,"`
	TimezoneName         string         `datastore:",noindex"`
	TimezoneLocation     *time.Location `datastore:"-,"`
	ExcludedRepoIds      []int          `datastore:",noindex"`
	DigestEmailAddress   string
	Frequency            string
	WeeklyDay            time.Weekday
}

func getAccount(c appengine.Context, githubUserId int) (*Account, error) {
	key := datastore.NewKey(c, "Account", "", int64(githubUserId), nil)
	account := new(Account)
	err := datastore.Get(c, key, account)
	if err != nil {
		return nil, err
	}

	err = initAccount(account)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func initAccount(account *Account) error {
	r := bytes.NewBuffer(account.OAuthTokenSerialized)
	err := gob.NewDecoder(r).Decode(&account.OAuthToken)
	if err != nil {
		return err
	}
	if len(account.TimezoneName) == 0 {
		account.TimezoneName = "America/Los_Angeles"
	}
	if len(account.Frequency) == 0 {
		account.Frequency = "daily"
	}
	account.TimezoneLocation, err = time.LoadLocation(account.TimezoneName)
	if err != nil {
		return err
	}
	return nil
}

func getAllAccounts(c appengine.Context) ([]Account, error) {
	q := datastore.NewQuery("Account")
	var accounts []Account
	_, err := q.GetAll(c, &accounts)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		err = initAccount(&accounts[i])
		if err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

func (account *Account) IsRepoIdExcluded(repoId int) bool {
	for i := range account.ExcludedRepoIds {
		if account.ExcludedRepoIds[i] == repoId {
			return true
		}
	}
	return false
}

func (account *Account) Put(c appengine.Context) error {
	w := new(bytes.Buffer)
	err := gob.NewEncoder(w).Encode(&account.OAuthToken)
	if err != nil {
		return err
	}
	account.OAuthTokenSerialized = w.Bytes()
	key := datastore.NewKey(c, "Account", "", int64(account.GitHubUserId), nil)
	_, err = datastore.Put(c, key, account)
	return err
}

func (account *Account) GetDigestEmailAddress(githubClient *github.Client) (string, error) {
	if len(account.DigestEmailAddress) > 0 {
		return account.DigestEmailAddress, nil
	}
	emails, _, err := githubClient.Users.ListEmails(nil)
	if err != nil {
		return "", err
	}
	// Prefer the primary, verified email
	for _, email := range emails {
		if email.Primary != nil && *email.Primary &&
			email.Verified != nil && *email.Verified {
			return *email.Email, nil
		}
	}
	// Then the first verified email
	for _, email := range emails {
		if email.Verified != nil && *email.Verified {
			return *email.Email, nil
		}
	}
	// Then just the first email
	for _, email := range emails {
		return *email.Email, nil
	}
	return "", errors.New("No email addresses found in GitHub account")
}
