package githop

import (
	"bytes"
	"encoding/gob"

	"appengine"
	"appengine/datastore"

	"code.google.com/p/goauth2/oauth"
)

type Account struct {
	GitHubUserId int `datastore:",noindex"`
	// The datastore API doesn't store maps, and the token contains one. We
	// thefore store a gob-serialized version instead.
	OAuthTokenSerialized []byte
	OAuthToken           oauth.Token `datastore:"-,"`
}

func getAccount(c appengine.Context, gitHubUserId int) (*Account, error) {
	key := datastore.NewKey(c, "Account", "", int64(gitHubUserId), nil)
	account := new(Account)
	err := datastore.Get(c, key, account)
	if err != nil {
		return nil, err
	}
	r := bytes.NewBuffer(account.OAuthTokenSerialized)
	err = gob.NewDecoder(r).Decode(&account.OAuthToken)
	return account, err
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
