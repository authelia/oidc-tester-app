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

	jwtIdentifier := session.Values["jwt_identifier"].(string)
	claims := claimsStorage[jwtIdentifier]

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
		fmt.Fprintf(res, "<p>Not logged yet...</p> <a href=\"/login\">Log in</a>")

		return
	}

	jwtIdentifier := session.Values["jwt_identifier"].(string)
	var claims Claims
	if c, ok := claimsStorage[jwtIdentifier]; ok {
		claims = c
	}

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
		"<p>Access Token Hash: %s</p>"+
		"<p>Code Hash: %s</p>"+
		"<p>Authentication Context Class Reference: %s</p>"+
		"<p>Authentication Methods Reference: %s</p>"+
		"<p>Audience: %s</p>"+
		"<p>Expires: %d</p>"+
		"<p>Issue Time: %d</p>"+
		"<p>Requested At: %d</p>"+
		"<p>Authorize Time: %d</p>"+
		"<p>Not Before: %d</p>"+
		"<p>Issuer: %s</p>"+
		"<p>JWT ID: %s</p>"+
		"<p>Subject: %s</p>"+
		"<p>Nonce: %s</p>"+
		"<p>Email: %s</p>"+
		"<p>Email Verified: %v</p>"+
		"<p>Groups: %s</p>"+
		"<p>Name: %s</p>"+
		"<p>Raw: %s</p>",
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
		rawIDTokenStorage[jwtIdentifier],
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
	fmt.Fprintf(res, "<p>This is the protected endpoint</p>"+
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
	jwtIdentifier := session.Values["jwt_identifier"].(string)
	claims := claimsStorage[jwtIdentifier]

	res.Header().Add("Content-Type", "text/html")

	if vars["type"] == "user" {
		if strings.EqualFold(vars["user"], claims.Subject) {
			fmt.Fprintf(res, "<p>This is the protected user endpoint</p>"+
				"<p id=\"message\">Access Granted. Your username is '%s'.</p>"+
				"<p id=\"access\">1</p>", vars["user"])

			return
		}
		fmt.Fprintf(res, "<p>This is the protected user endpoint</p>"+
			"<p id=\"message\">Access Denied. Requires user '%s'.</p>"+
			"<p id=\"access\">0</p>", vars["user"])

		return
	}

	if vars["type"] != "group" {
		fmt.Fprintf(res, "<p>This is the protected invalid endpoint</p>")

		return
	}

	if isStringInSlice(vars["group"], claims.Groups) {
		fmt.Fprintf(res, "<p>This is the protected group endpoint</p>"+
			"<p id=\"message\">Access Granted. You have the group '%s'.</p>"+
			"<p id=\"access\">1</p>", vars["group"])

		return
	}
	fmt.Fprintf(res, "<p>This is the protected group endpoint</p>"+
		"<p id=\"message\">Access Denied. Requires group '%s'.</p>"+
		"<p id=\"access\">0</p>", vars["group"])
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

	claimsStorage[claims.JWTIdentifier] = claims
	rawIDTokenStorage[claims.JWTIdentifier] = rawIDToken

	session.Values["jwt_identifier"] = claims.JWTIdentifier
	session.Values["logged"] = true

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
