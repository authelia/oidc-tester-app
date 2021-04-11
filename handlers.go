package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func JSONHandler(res http.ResponseWriter, req *http.Request) {
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

func IndexHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if logged, ok := session.Values["logged"].(bool); !ok || !logged {
		fmt.Fprintf(res, "<p>Not logged yet...</p> <a href=\"/login\">Log in</a>")
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
		session.Values["idToken"],
	)
}

func LoginHandler(res http.ResponseWriter, req *http.Request) {
	http.Redirect(res, req, oauth2Config.AuthCodeURL("random-string-here"), http.StatusFound)
}

func LogoutHandler(res http.ResponseWriter, req *http.Request) {
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

	http.Redirect(res, req, "/", 302)
}

func OAuthCallbackHandler(res http.ResponseWriter, req *http.Request) {
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
	session.Values["idToken"] = rawIDToken
	if err = session.Save(req, res); err != nil {
		fmt.Println(err.Error())
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(res, req, "/", 302)
}
