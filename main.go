package main

import (
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var options Options

var oidcProvider *oidc.Provider
var verifier *oidc.IDTokenVerifier
var store = sessions.NewCookieStore([]byte("secret-key"))

var oauth2Config oauth2.Config

func main() {
	gob.Register(Claims{})

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	rootCmd := &cobra.Command{Use: "oidc-tester-app", Run: root}

	rootCmd.Flags().StringVar(&options.Host, "host", "0.0.0.0", "Specifies the host to listen on")
	rootCmd.Flags().IntVar(&options.Port, "port", 8080, "Specifies the port to listen on")
	rootCmd.Flags().StringVarP(&options.RedirectDomain, "redirect-domain", "d", "localhost", "Specifies the domain used to generate the RedirectURL")
	rootCmd.Flags().StringVar(&options.ClientID, "id", "", "Specifies the OpenID Connect Client ID")
	rootCmd.Flags().StringVarP(&options.ClientSecret, "secret", "s", "", "Specifies the OpenID Connect Client Secret")
	rootCmd.Flags().StringVarP(&options.Issuer, "issuer", "i", "", "Specifies the URL for the OpenID Connect OP")
	rootCmd.Flags().StringVar(&options.Scopes, "scopes", "openid,profile,email,groups", "Specifies the OpenID Connect scopes to request")
	rootCmd.Flags().StringVar(&options.CookieName, "cookie-name", "oidc-client", "Specifies the storage cookie name to use")
	rootCmd.Flags().StringSliceVar(&options.Filters, "filters", []string{}, "If specified filters the specified text from html output (not json) out of the email addresses, display names, audience, etc")
	rootCmd.Flags().StringSliceVar(&options.GroupsFilter, "groups-filter", []string{}, "If specified only shows the groups in this list")

	_ = rootCmd.MarkFlagRequired("id")
	_ = rootCmd.MarkFlagRequired("secret")
	_ = rootCmd.MarkFlagRequired("issuer")

	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}

func root(cmd *cobra.Command, args []string) {
	options.RedirectURL = fmt.Sprintf("https://%s:%d/oauth2/callback", options.RedirectDomain, options.Port)

	fmt.Printf("Provider URL: %s.\nRedirect URL: %s.\n", options.Issuer, options.RedirectURL)

	var err error
	oidcProvider, err = oidc.NewProvider(context.Background(), options.Issuer)
	if err != nil {
		panic(err)
	}

	verifier = oidcProvider.Verifier(&oidc.Config{ClientID: options.ClientID})
	oauth2Config = oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		RedirectURL:  options.RedirectURL,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       strings.Split(options.Scopes, ","),
	}

	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/oauth2/callback", oauthCallbackHandler)
	r.HandleFunc("/json", jsonHandler)
	r.HandleFunc("/protected", protectedBasicHandler)
	r.HandleFunc("/protected/{type:group|user}/{group}", protectedAdvancedHandler)

	fmt.Printf("Server Address http://%s:%d/ (%s)\n\nListening...", options.RedirectDomain, options.Port, options.Host)

	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", options.Host, options.Port), r))
}
