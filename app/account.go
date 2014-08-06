package githop

import (
	"bytes"
	"encoding/gob"
	"time"

	"appengine"
	"appengine/datastore"

	"code.google.com/p/goauth2/oauth"
)

type Account struct {
	GitHubUserId int `datastore:",noindex"`
	// The datastore API doesn't store maps, and the token contains one. We
	// thefore store a gob-serialized version instead.
	OAuthTokenSerialized []byte
	OAuthToken           oauth.Token    `datastore:"-,"`
	TimezoneName         string         `datastore:",noindex"`
	TimezoneLocation     *time.Location `datastore:"-,"`
}

func getAccount(c appengine.Context, gitHubUserId int) (*Account, error) {
	key := datastore.NewKey(c, "Account", "", int64(gitHubUserId), nil)
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
	account.TimezoneLocation, err = time.LoadLocation(account.TimezoneName)
	if err != nil {
		return err
	}
	return nil
}

func getAllAccounts(c appengine.Context, accounts *[]Account) error {
	q := datastore.NewQuery("Account")
	_, err := q.GetAll(c, accounts)
	if err != nil {
		return err
	}
	for i, _ := range *accounts {
		err = initAccount(&(*accounts)[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (account *Account) put(c appengine.Context) error {
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
