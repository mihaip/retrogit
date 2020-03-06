package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"

	"google.golang.org/appengine"

	"github.com/gorilla/sessions"
)

type SessionConfig struct {
	AuthenticationKey string
	EncryptionKey     string
	CookieName        string
	UserIdKey         string
}

func initSession() (sessionStore *sessions.CookieStore, sessionConfig SessionConfig) {
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
	return
}
