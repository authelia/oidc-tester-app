package main

type Claims struct {
	JWTIdentifier                       string   `json:"jti"`
	Issuer                              string   `json:"iss"`
	Subject                             string   `json:"sub"`
	Nonce                               string   `json:"nonce"`
	Expires                             int64    `json:"exp"`
	IssueTime                           int64    `json:"iat"`
	RequestedAt                         int64    `json:"rat"`
	AuthorizeTime                       int64    `json:"auth_time"`
	NotBefore                           int64    `json:"nbf"`
	Audience                            []string `json:"aud"`
	Scope                               []string `json:"scp"`
	ScopeString                         string   `json:"scope"`
	AccessTokenHash                     string   `json:"at_hash"`
	CodeHash                            string   `json:"c_hash"`
	AuthenticationContextClassReference string   `json:"acr"`
	AuthenticationMethodsReference      []string `json:"amr"`

	Name                string       `json:"name"`
	GivenName           string       `json:"given_name"`
	FamilyName          string       `json:"family_name"`
	MiddleName          string       `json:"middle_name"`
	Nickname            string       `json:"nickname"`
	PreferredUsername   string       `json:"preferred_username"`
	Profile             string       `jsoon:"profile"`
	Picture             string       `json:"picture"`
	Website             string       `json:"website"`
	Gender              string       `json:"gender"`
	Birthdate           string       `json:"birthdate"`
	ZoneInfo            string       `json:"zoneinfo"`
	Locale              string       `json:"locale"`
	UpdatedAt           int64        `json:"updated_at"`
	Email               string       `json:"email"`
	EmailAlts           []string     `json:"alt_emails"`
	EmailVerified       bool         `json:"email_verified"`
	PhoneNumber         string       `json:"phone_number"`
	PhoneNumberVerified bool         `json:"phone_number_verified"`
	Address             ClamsAddress `json:"address"`
	Groups              []string     `json:"groups"`
}

type ClamsAddress struct {
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

type Options struct {
	Host         string
	Port         int
	ClientID     string
	ClientSecret string
	Issuer       string
	PublicURL    string
	Scopes       string
	CookieName   string
	Filters      []string
	GroupsFilter []string
}
