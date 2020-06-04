package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var clientID string
var clientSecret string
var oidcProvider *oidc.Provider
var oidcProviderURL string
var redirectURI string
var scopes string
var cookieName string

var verifier *oidc.IDTokenVerifier
var store = sessions.NewCookieStore([]byte("secret-key"))

var oauth2Config oauth2.Config

func init() {
	// Disable TLS verification. It's fine for testing purpose but should not be done in production.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	flag.StringVar(&clientID, "client-id", "", "client id")
	flag.StringVar(&clientSecret, "client-secret", "", "client secret")
	flag.StringVar(&oidcProviderURL, "oidc-provider-url", "", "OIDC provider URL")
	flag.StringVar(&redirectURI, "redirect-uri", "http://localhost:8080/oauth2/callback", "redirection URI")
	flag.StringVar(&scopes, "scopes", "openid,profile,email", "scopes")
	flag.StringVar(&cookieName, "cookie-name", "oidc-tester-app", "cookie name")

	flag.Parse()

	var err error
	oidcProvider, err = oidc.NewProvider(context.Background(), oidcProviderURL)
	if err != nil {
		panic(err)
	}

	verifier = oidcProvider.Verifier(&oidc.Config{ClientID: clientID})
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: oidcProvider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: strings.Split(scopes, ","),
	}
}

func Home(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, cookieName)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if logged, ok := session.Values["logged"].(bool); !ok || !logged {
		fmt.Fprintf(res, "<p>Not logged yet...</p> <a href=\"/login\">Log in</a>")
		return
	}

	res.Header().Add("Content-Type", "text/html")
	fmt.Fprintf(res, "<p>Logged in as %s!</p><a href=\"/logout\">Log out</a>", session.Values["email"])
}

func Login(res http.ResponseWriter, req *http.Request) {
	http.Redirect(res, req, oauth2Config.AuthCodeURL("random-string-here"), http.StatusFound)
}

func Logout(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, cookieName)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	// Reset the session
	session.Values = make(map[interface{}]interface{})

	if err := session.Save(req, res); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(res, req, "/", 302)
}

func OAuthCallback(res http.ResponseWriter, req *http.Request) {
	// The state should be checked here in production

	oauth2Token, err := oauth2Config.Exchange(req.Context(), req.URL.Query().Get("code"))
	if err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		fmt.Println("Missing id_token")
		http.Error(res, "Missing id_token", http.StatusInternalServerError)
		return
	}

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(req.Context(), rawIDToken)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := store.Get(req, cookieName)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["email"] = claims.Email
	session.Values["logged"] = true
	if err = session.Save(req, res); err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(res, req, "/", 302)
}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/", Home)
	r.HandleFunc("/login", Login)
	r.HandleFunc("/logout", Logout)
	r.HandleFunc("/oauth2/callback", OAuthCallback)

	fmt.Println("Listening...")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", r))
}
