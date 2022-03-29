package main

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
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

	tpl := indexTplData{
		Error: req.FormValue("error"),
	}

	if logged, ok := session.Values["logged"].(bool); ok && logged {
		tpl.LoggedIn = true
		tpl.Claims = session.Values["claims"].(Claims)

		if len(options.GroupsFilter) >= 1 {
			for _, group := range tpl.Claims.Groups {
				if isStringInSlice(group, options.GroupsFilter) {
					tpl.Groups = append(tpl.Groups, filterText(group, options.Filters))
				}
			}
		} else {
			tpl.Groups = filterSliceOfText(tpl.Claims.Groups, options.Filters)
		}

		tpl.Claims.PreferredUsername = filterText(tpl.Claims.PreferredUsername, options.Filters)
		tpl.Claims.Audience = filterSliceOfText(tpl.Claims.Audience, options.Filters)
		tpl.Claims.Issuer = filterText(tpl.Claims.Issuer, options.Filters)
		tpl.Claims.Email = filterText(tpl.Claims.Email, options.Filters)
		tpl.Claims.Name = filterText(tpl.Claims.Name, options.Filters)
		tpl.RawToken = rawTokens[tpl.Claims.JWTIdentifier]
	}

	res.Header().Add("Content-Type", "text/html")

	if err = indexTpl.Execute(res, tpl); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func errorHandler(res http.ResponseWriter, req *http.Request) {
	tpl := errorTplData{
		Error:            req.FormValue("error"),
		ErrorDescription: req.FormValue("error_description"),
		ErrorURI:         req.FormValue("error_uri"),
		State:            req.FormValue("state"),
	}

	res.Header().Add("Content-Type", "text/html")

	if err := errorTpl.Execute(res, tpl); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func protectedHandler(basic bool) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
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

		tpl := protectedTplData{}

		vars := mux.Vars(req)

		tpl.Vars.Type = vars["type"]
		tpl.Vars.Value = vars["name"]

		if basic {
			tpl.Vars.ProtectedSecret = "2511140547"
			tpl.Vars.Type = "basic"
		} else {
			tpl.Claims = session.Values["claims"].(Claims)
			hash := sha512.New()

			hash.Write([]byte(tpl.Vars.Value))

			tpl.Vars.ProtectedSecret = fmt.Sprintf("%x", hash.Sum(nil))
		}

		res.Header().Add("Content-Type", "text/html")

		if err = protectedTpl.Execute(res, tpl); err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
	}
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
	if req.FormValue("error") != "" {
		http.Redirect(res, req, fmt.Sprintf("/error?%s", req.Form.Encode()), http.StatusFound)

		return
	}

	// The state should be checked here in production
	oauth2Token, err := oauth2Config.Exchange(req.Context(), req.URL.Query().Get("code"))

	if err != nil {
		fmt.Errorf("unable to exchange authorization code for tokens: %w", err)
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		fmt.Errorf("missing id token")
		http.Error(res, "Missing id_token", http.StatusInternalServerError)

		return
	}

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(req.Context(), rawIDToken)
	if err != nil {
		fmt.Errorf("unable to verify id token or token is invalid: %w", err)
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	// Extract custom claims
	claims := Claims{}

	if err := idToken.Claims(&claims); err != nil {
		fmt.Errorf("unable to retrieve id token claims: %w", err)
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	session, err := store.Get(req, options.CookieName)
	if err != nil {
		fmt.Errorf("unable to get session from cookie: %w", err)
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	session.Values["claims"] = claims
	session.Values["logged"] = true
	rawTokens[claims.JWTIdentifier] = rawIDToken

	if err = session.Save(req, res); err != nil {
		fmt.Errorf("unable to save session: %w", err)
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	if redirectUrl, ok := session.Values["redirect-url"].(string); ok {
		http.Redirect(res, req, redirectUrl, http.StatusFound)

		return
	}

	http.Redirect(res, req, "/", http.StatusFound)
}
