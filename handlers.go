package main

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

func jsonHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Content-Type", "application/json")
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		writeErr(res, err, "error getting session", http.StatusInternalServerError)
		return
	}

	claims := session.Values["claims"].(Claims)

	if err = json.NewEncoder(res).Encode(claims); err != nil {
		writeErr(res, err, "error encoding claims", http.StatusInternalServerError)
		return
	}
}

func indexHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		writeErr(res, err, "error getting session", http.StatusInternalServerError)
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
		writeErr(res, err, "error executing index template", http.StatusInternalServerError)
	}
}

func errorHandler(res http.ResponseWriter, req *http.Request) {
	tpl := errorTplData{
		Error:            req.FormValue("error"),
		ErrorDescription: req.FormValue("error_description"),
		ErrorURI:         req.FormValue("error_uri"),
		State:            req.FormValue("state"),
	}

	log.Logger.Error().
		Str("error_name", tpl.Error).
		Str("description", tpl.ErrorDescription).
		Str("uri", tpl.ErrorURI).
		Str("state", tpl.State).
		Msg("received oidc authorization server error")

	res.Header().Add("Content-Type", "text/html")

	if err := errorTpl.Execute(res, tpl); err != nil {
		writeErr(res, err, "error executing error template", http.StatusInternalServerError)
	}
}

func protectedHandler(basic bool) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		session, err := store.Get(req, options.CookieName)

		if err != nil {
			writeErr(res, err, "error getting session", http.StatusInternalServerError)
			return
		}

		if logged, ok := session.Values["logged"].(bool); !ok || !logged {
			session.Values["redirect-url"] = req.URL.Path

			if err = session.Save(req, res); err != nil {
				writeErr(res, err, "error saving session", http.StatusInternalServerError)
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

		if val, ok := session.Values["ac_url"]; ok {
			if acurl, ok := val.(*url.URL); ok {
				tpl.AuthorizeCodeURL = acurl.String()
			}
		}

		res.Header().Add("Content-Type", "text/html")

		if err = protectedTpl.Execute(res, tpl); err != nil {
			writeErr(res, err, "error executing template", http.StatusInternalServerError)
		}
	}
}

func loginHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)

	if err != nil {
		writeErr(res, nil, "error getting cookie", http.StatusInternalServerError)
		return
	}

	session.Values["redirect-url"] = "/"
	if err = session.Save(req, res); err != nil {
		writeErr(res, err, "error saving session", http.StatusInternalServerError)
		return
	}

	http.Redirect(res, req, oauth2Config.AuthCodeURL("random-string-here"), http.StatusFound)
}

func logoutHandler(res http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, options.CookieName)
	if err != nil {
		writeErr(res, err, "error getting cookie", http.StatusInternalServerError)
		return
	}

	// Reset the session
	session.Values = make(map[interface{}]interface{})

	if err = session.Save(req, res); err != nil {
		writeErr(res, err, "error saving session", http.StatusInternalServerError)
		return
	}

	http.Redirect(res, req, "/", http.StatusFound)
}

func oauthCallbackHandler(res http.ResponseWriter, req *http.Request) {
	if req.FormValue("error") != "" {
		http.Redirect(res, req, fmt.Sprintf("/error?%s", req.Form.Encode()), http.StatusFound)

		return
	}

	var (
		token      *oauth2.Token
		idToken    *oidc.IDToken
		err        error
		idTokenRaw string
		ok         bool
	)

	// The state should be checked here in production
	if token, err = oauth2Config.Exchange(req.Context(), req.URL.Query().Get("code")); err != nil {
		writeErr(res, err, "unable to exchange authorization code for tokens", http.StatusInternalServerError)
		return
	}

	// Extract the ID Token from OAuth2 token.
	if idTokenRaw, ok = token.Extra("id_token").(string); !ok {
		writeErr(res, nil, "missing id token", http.StatusInternalServerError)
		return
	}

	// Parse and verify ID Token payload.
	if idToken, err = verifier.Verify(req.Context(), idTokenRaw); err != nil {
		writeErr(res, err, "unable to verify id token or token is invalid", http.StatusInternalServerError)
		return
	}

	// Extract custom claims
	claims := Claims{}

	var session *sessions.Session

	if err = idToken.Claims(&claims); err != nil {
		writeErr(res, err, "unable to retrieve id token claims", http.StatusInternalServerError)
		return
	}

	if session, err = store.Get(req, options.CookieName); err != nil {
		writeErr(res, err, "unable to get session from cookie", http.StatusInternalServerError)
		return
	}

	session.Values["claims"] = claims
	session.Values["logged"] = true
	session.Values["ac_url"] = req.URL
	rawTokens[claims.JWTIdentifier] = idTokenRaw

	if err = session.Save(req, res); err != nil {
		writeErr(res, err, "unable to save session", http.StatusInternalServerError)
		return
	}

	var redirectUrl string

	if redirectUrl, ok = session.Values["redirect-url"].(string); ok {
		http.Redirect(res, req, redirectUrl, http.StatusFound)
		return
	}

	http.Redirect(res, req, "/", http.StatusFound)
}

func writeErr(res http.ResponseWriter, err error, msg string, statusCode int) {
	switch {
	case err == nil:
		log.Logger.Error().
			Msg(msg)

		http.Error(res, msg, statusCode)
	default:
		log.Logger.Error().
			Err(err).
			Msg(msg)

		http.Error(res, fmt.Errorf("%s: %w", msg, err).Error(), statusCode)
	}
}
