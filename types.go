package main

type Claims struct {
	AccessTokenHash                     string   `json:"at_hash"`
	CodeHash                            string   `json:"c_hash"`
	AuthenticationContextClassReference string   `json:"acr"`
	AuthenticationMethodsReference      string   `json:"amr"`
	Audience                            []string `json:"aud"`
	Expires                             float64  `json:"exp"`
	IssueTime                           float64  `json:"iat"`
	RequestedAt                         float64  `json:"rat"`
	AuthorizeTime                       float64  `json:"auth_time"`
	NotBefore                           float64  `json:"nbf"`
	Issuer                              string   `json:"iss"`
	Scope                               []string `json:"scp"`
	ScopeString                         string   `json:"scope"`
	JWTIdentifier                       string   `json:"jti"`
	Subject                             string   `json:"sub"`
	Nonce                               string   `json:"nonce"`
	Email                               string   `json:"email"`
	EmailVerified                       bool     `json:"email_verified"`
	Groups                              []string `json:"groups"`
	Name                                string   `json:"name"`
}

type Options struct {
	Host           string
	Port           int
	ClientID       string
	ClientSecret   string
	Issuer         string
	RedirectScheme string
	RedirectURL    string
	RedirectDomain string
	Scopes         string
	CookieName     string
	Filters        []string
	GroupsFilter   []string
}
