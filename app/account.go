package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"time"

	"google.golang.org/appengine/v2/datastore"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

type Account struct {
	GitHubUserId int64 `datastore:",noindex"`
	// The datastore API doesn't store maps, and the token contains one. We
	// thefore store a gob-serialized version instead.
	OAuthTokenSerialized []byte
	OAuthToken           oauth2.Token   `datastore:"-,"`
	TimezoneName         string         `datastore:",noindex"`
	TimezoneLocation     *time.Location `datastore:"-,"`
	HasTimezoneSet       bool           `datastore:"-,"`
	ExcludedRepoIds      []int64        `datastore:",noindex"`
	DigestEmailAddress   string
	Frequency            string
	WeeklyDay            time.Weekday
}

func getAccount(c context.Context, githubUserId int64) (*Account, error) {
	key := datastore.NewKey(c, "Account", "", githubUserId, nil)
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
	account.HasTimezoneSet = len(account.TimezoneName) > 0
	if !account.HasTimezoneSet {
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

func getAllAccounts(c context.Context) ([]Account, error) {
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

func (account *Account) IsRepoIdExcluded(repoId int64) bool {
	for i := range account.ExcludedRepoIds {
		if account.ExcludedRepoIds[i] == repoId {
			return true
		}
	}
	return false
}

func (account *Account) Put(c context.Context) error {
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

func (account *Account) Delete(c context.Context) error {
	key := datastore.NewKey(c, "Account", "", int64(account.GitHubUserId), nil)
	err := datastore.Delete(c, key)
	return err
}

func (account *Account) GetDigestEmailAddress(c context.Context, githubClient *github.Client) (string, error) {
	if len(account.DigestEmailAddress) > 0 {
		return account.DigestEmailAddress, nil
	}
	emails, _, err := githubClient.Users.ListEmails(c, nil)
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
