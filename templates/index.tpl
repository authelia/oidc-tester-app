<!doctype html>

<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>{{ or .Title "Authelia OIDC app" }}</title>
    {{ if not (eq .Description "") }}<meta name="description" content="{{ .Description }}">{{ end }}
    <meta name="author" content="Authelia">

    <meta property="og:title" content="{{ .Title }}">
    <meta property="og:type" content="website">
    {{ if not (eq .Description "") }}<meta property="og:description" content="{{ .Description }}">{{ end }}

    <link rel="stylesheet" href="/static/styles.css?v=1.0">

</head>

<body>
    <div id="container">
        {{- if .LoggedIn }}
        <p id="welcome">Logged in as {{ or .Claims.UserInfo.PreferredUsername .Claims.IDToken.Subject "unknown" }}!</p>
        <p><a href="/logout" id="log-out">Log out</a></p>
        <p>Access Token Hash: <span id="claim-at_hash">{{ .Claims.IDToken.AccessTokenHash }}</span></p>
        <p>Code Hash: <span id="claim-c_hash">{{ .Claims.IDToken.CodeHash }}</span></p>
        <p>Authentication Context Class Reference: <span id="claim-acr">{{ .Claims.IDToken.AuthenticationContextClassReference }}</span></p>
        <p>Authentication Methods Reference: <span id="claim-amr">{{ stringsJoin .Claims.IDToken.AuthenticationMethodsReference ", " }}</span></p>
        <p>Audience: <span id="claim-aud">{{ stringsJoin .Claims.IDToken.Audience ", " }}</span></p>
        <p>Expires: <span id="claim-exp">{{ .Claims.IDToken.Expires }}</span></p>
        <p>Issue Time: <span id="claim-iat">{{ .Claims.IDToken.IssueTime }}</span></p>
        <p>Requested At: <span id="claim-rat">{{ .Claims.IDToken.RequestedAt }}</span></p>
        <p>Authorize Time: <span id="claim-auth_at">{{ .Claims.IDToken.AuthorizeTime }}</span></p>
        <p>Not Before: <span id="claim-nbf">{{ .Claims.IDToken.NotBefore }}</span></p>
        <p>Issuer: <span id="claim-iss">{{ .Claims.IDToken.Issuer }}</span></p>
        <p>JWT ID: <span id="claim-jti">{{ .Claims.IDToken.JWTIdentifier }}</span></p>
        <p>Subject: <span id="claim-sub">{{ .Claims.IDToken.Subject }}</span></p>
        <p>Nonce: <span id="claim-nonce">{{ .Claims.IDToken.Nonce }}</span></p>
        <p>Name: <span id="claim-name">{{ .Claims.UserInfo.Name }}</span></p>
        <p>Name (ID Token): <span id="claim-id-token-name">{{ .Claims.IDToken.Name }}</span></p>
        <p>Given Name: <span id="claim-given_name">{{ .Claims.UserInfo.GivenName }}</span></p>
        <p>Given Name (ID Token): <span id="claim-id-token-given_name">{{ .Claims.IDToken.GivenName }}</span></p>
        <p>Family Name: <span id="claim-family_name">{{ .Claims.UserInfo.FamilyName }}</span></p>
        <p>Family Name (ID Token): <span id="claim-id-token-family_name">{{ .Claims.IDToken.FamilyName }}</span></p>
        <p>Middle Name: <span id="claim-middle_name">{{ .Claims.UserInfo.MiddleName }}</span></p>
        <p>Middle Name (ID Token): <span id="claim-id-token-middle_name">{{ .Claims.IDToken.MiddleName }}</span></p>
        <p>Nickname: <span id="claim-nickname">{{ .Claims.UserInfo.Nickname }}</span></p>
        <p>Nickname (ID Token): <span id="claim-id-token-nickname">{{ .Claims.IDToken.Nickname }}</span></p>
        <p>Preferred Username: <span id="claim-preferred_username">{{ .Claims.UserInfo.PreferredUsername }}</span></p>
        <p>Preferred Username (ID Token): <span id="claim-id-token-preferred_username">{{ .Claims.IDToken.PreferredUsername }}</span></p>
        <p>Profile: <span id="claim-profile">{{ .Claims.UserInfo.Profile }}</span></p>
        <p>Profile (ID Token): <span id="claim-id-token-profile">{{ .Claims.IDToken.Profile }}</span></p>
        <p>Website: <span id="claim-website">{{ .Claims.UserInfo.Website }}</span></p>
        <p>Website (ID Token): <span id="claim-id-token-website">{{ .Claims.IDToken.Website }}</span></p>
        <p>Gender: <span id="claim-gender">{{ .Claims.UserInfo.Gender }}</span></p>
        <p>Gender (ID Token): <span id="claim-id-token-gender">{{ .Claims.IDToken.Gender }}</span></p>
        <p>Birthdate: <span id="claim-birthdate">{{ .Claims.UserInfo.Birthdate }}</span></p>
        <p>Birthdate (ID Token): <span id="claim-id-token-birthdate">{{ .Claims.IDToken.Birthdate }}</span></p>
        <p>ZoneInfo: <span id="claim-zoneinfo">{{ .Claims.UserInfo.ZoneInfo }}</span></p>
        <p>ZoneInfo (ID Token): <span id="claim-id-token-zoneinfo">{{ .Claims.IDToken.ZoneInfo }}</span></p>
        <p>Locale: <span id="claim-locale">{{ .Claims.UserInfo.Locale }}</span></p>
        <p>Locale (ID Token): <span id="claim-id-token-locale">{{ .Claims.IDToken.Locale }}</span></p>
        <p>Updated At: <span id="claim-updated_at">{{ .Claims.UserInfo.UpdatedAt }}</span></p>
        <p>Updated At (ID Token): <span id="claim-id-token-updated_at">{{ .Claims.IDToken.UpdatedAt }}</span></p>
        <p>Email: <span id="claim-email">{{ .Claims.UserInfo.Email }}</span></p>
        <p>Email (ID Token): <span id="claim-id-token-email">{{ .Claims.IDToken.Email }}</span></p>
        <p>Email Alts: <span id="claim-alt_emails">{{ .Claims.UserInfo.EmailAlts }}</span></p>
        <p>Email Alts (ID Token): <span id="claim-id-token-alt_emails">{{ .Claims.IDToken.EmailAlts }}</span></p>
        <p>Email Verified: <span id="claim-email_verified">{{ .Claims.UserInfo.EmailVerified }}</span></p>
        <p>Email Verified (ID Token): <span id="claim-id-token-email_verified">{{ .Claims.IDToken.EmailVerified }}</span></p>
        <p>Phone Number: <span id="claim-phone_number">{{ .Claims.UserInfo.PhoneNumber }}</span></p>
        <p>Phone Number (ID Token): <span id="claim-id-token-phone_number">{{ .Claims.IDToken.PhoneNumber }}</span></p>
        <p>Phone Number Verified: <span id="claim-phone_number_verified">{{ .Claims.UserInfo.PhoneNumberVerified }}</span></p>
        <p>Phone Number Verified (ID Token): <span id="claim-id-token-phone_number_verified">{{ .Claims.IDToken.PhoneNumberVerified }}</span></p>
        <p>Groups: <span id="claim-groups">{{ stringsJoin .Groups ", " }}</span></p>
        <p>Groups (ID Token): <span id="claim-id-token-groups">{{ stringsJoin .Groups ", " }}</span></p>
        <p>Raw: <span id="raw">{{ .RawToken }}</span></p>
        <p>Authorize Code URL: <span id="auth-code-url">{{ .AuthorizeCodeURL }}</span></p>
        {{- else }}
        <p>Not logged yet...</p> <a id="login-link" href="/login">Log in</a>
        {{- end }}
    </div>
</body>
</html>
