package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"strings"
)

func jsonHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Content-Type", "application/json")
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	claims := session.Values["claims"].(Claims)

	if err := json.NewEncoder(res).Encode(claims); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}
}

func indexHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	if logged, ok := session.Values["logged"].(bool); !ok || !logged {
		fmt.Fprintf(res, "<p>Not logged yet...</p> <a id=\"login-link\" href=\"/login\">Log in</a>")

		return
	}

	claims := session.Values["claims"].(Claims)

	var groups []string
	if len(options.GroupsFilter) >= 1 {
		for _, group := range claims.Groups {
			if isStringInSlice(group, options.GroupsFilter) {
				groups = append(groups, filterText(group, options.Filters))
			}
		}
	} else {
		groups = filterSliceOfText(claims.Groups, options.Filters)
	}

	res.Header().Add("Content-Type", "text/html")
	fmt.Fprintf(res, "<p>Logged in as %s!</p>"+
		"<p><a href=\"/logout\">Log out</a></p>"+
		"<p>Access Token Hash: <span id=\"oidc-access-token-hash\">%s</span></p>"+
		"<p>Code Hash: <span id=\"oidc-code-hash\">%s</span></p>"+
		"<p>Authentication Context Class Reference: <span id=\"oidc-auth-ctx-class-ref\">%s</span></p>"+
		"<p>Authentication Methods Reference: <span id=\"oidc-auth-method-ref\">%s</span></p>"+
		"<p>Audience: <span id=\"oidc-audience\">%s</span></p>"+
		"<p>Expires: <span id=\"oidc-expires\">%d</span></p>"+
		"<p>Issue Time: <span id=\"oidc-issue-time\">%d</span></p>"+
		"<p>Requested At: <span id=\"requested-at\">%d</span></p>"+
		"<p>Authorize Time: <span id=\"oidc-auth-at\">%d</span></p>"+
		"<p>Not Before: <span id=\"oidc-not-before\">%d</span></p>"+
		"<p>Issuer: <span id=\"oidc-issuer\">%s</span></p>"+
		"<p>JWT ID: <span id=\"oidc-jwt-id\">%s</span></p>"+
		"<p>Subject: <span id=\"oidc-subj\">%s</span></p>"+
		"<p>Nonce: <span id=\"oidc-nonce\">%s</span></p>"+
		"<p>Email: <span id=\"oidc-email\">%s</span></p>"+
		"<p>Email Verified: <span id=\"oidc-email-verified\">%v</span></p>"+
		"<p>Groups: <span id=\"oidc-groups\">%s</span></p>"+
		"<p>Name: <span id=\"oidc-name\">%s</span></p>"+
		"<p>Raw: <span id=\"oidc-raw\">%s</span></p>",
		filterText(claims.Subject, options.Filters),
		claims.AccessTokenHash,
		claims.CodeHash,
		claims.AuthenticationContextClassReference,
		claims.AuthenticationMethodsReference,
		filterSliceOfText(claims.Audience, options.Filters),
		claims.Expires,
		claims.IssueTime,
		claims.RequestedAt,
		claims.AuthorizeTime,
		claims.NotBefore,
		filterText(claims.Issuer, options.Filters),
		claims.JWTIdentifier,
		filterText(claims.Subject, options.Filters),
		claims.Nonce,
		filterText(claims.Email, options.Filters),
		claims.EmailVerified,
		strings.Join(groups, ", "),
		filterText(claims.Name, options.Filters),
		rawTokens[claims.JWTIdentifier],
	)
}

func protectedBasicHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	if logged, ok := session.Values["logged"].(bool); !ok || !logged {
		session.Values["redirect-url"] = req.URL.Path
		if err = session.Save(req, res); err != nil {
			fmt.Println(err.Error())
			http.Error(res, err.Error(), http.StatusInternalServerError)

			return
		}

		http.Redirect(res, req, oauth2Config.AuthCodeURL("random-string-here"), http.StatusFound)

		return
	}

	res.Header().Add("Content-Type", "text/html")
	fmt.Fprintf(res, "<p id=\"message\">This is the protected endpoint</p>"+
		"<p id=\"protected-secret\">2511140547</p>")
}

func protectedAdvancedHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	if logged, ok := session.Values["logged"].(bool); !ok || !logged {
		session.Values["redirect-url"] = req.URL.Path

		if err = session.Save(req, res); err != nil {
			fmt.Println(err.Error())
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(res, req, oauth2Config.AuthCodeURL("random-string-here"), http.StatusFound)

		return
	}

	vars := mux.Vars(req)
	claims := session.Values["claims"].(Claims)

	res.Header().Add("Content-Type", "text/html")

	if vars["type"] == "user" {
		if strings.EqualFold(vars["user"], claims.Subject) {
			fmt.Fprintf(res, "<p id=\"message\">This is the protected user endpoint</p>"+
				"<p id=\"message-grant\">Access Granted. Your username is '<span id=\"user\">%s</span>'.</p>"+
				"<p id=\"access-granted\">1</p>", vars["user"])

			return
		}
		fmt.Fprintf(res, "<p id=\"message\">This is the protected user endpoint</p>"+
			"<p id=\"grant-message\">Access Denied. Requires user '<span id=\"user\">%s</span>'.</p>"+
			"<p id=\"access-granted\">0</p>", vars["user"])

		return
	}

	if vars["type"] != "group" {
		fmt.Fprintf(res, "<p id=\"message\">This is the protected invalid endpoint</p>")

		return
	}

	if isStringInSlice(vars["group"], claims.Groups) {
		fmt.Fprintf(res, "<p id=\"message\">This is the protected group endpoint</p>"+
			"<p id=\"grant-message\">Access Granted. You have the group '<span id=\"group\">%s</span>'.</p>"+
			"<p id=\"access-granted\">1</p>", vars["group"])

		return
	}
	fmt.Fprintf(res, "<p id=\"message\">This is the protected group endpoint</p>"+
		"<p id=\"grant-message\">Access Denied. Requires group '<span id=\"group\">%s</span>'.</p>"+
		"<p id=\"access-granted\">0</p>", vars["group"])
}

func loginHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	session.Values["redirect-url"] = "/"
	if err = session.Save(req, res); err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	http.Redirect(res, req, oauth2Config.AuthCodeURL("random-string-here"), http.StatusFound)
}

func logoutHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

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

	http.Redirect(res, req, "/", http.StatusFound)
}

func oauthCallbackHandler(res http.ResponseWriter, req *http.Request) {
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
	claims := Claims{}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	session, err := store.Get(req, options.CookieName)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	session.Values["claims"] = claims
	session.Values["logged"] = true
	rawTokens[claims.JWTIdentifier] = rawIDToken

	if err = session.Save(req, res); err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	if redirectUrl, ok := session.Values["redirect-url"].(string); ok {
		http.Redirect(res, req, redirectUrl, http.StatusFound)

		return
	}

	http.Redirect(res, req, "/", http.StatusFound)
}
