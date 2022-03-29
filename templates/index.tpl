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

    <link rel="stylesheet" href="styles.css?v=1.0">

</head>

<body>
    <div id="container">
        {{- if .LoggedIn }}
        <p id="welcome">Logged in as {{ or .Claims.PreferredUsername .Claims.Subject "unknown" }}!</p>
        <p><a href="/logout" id="log-out">Log out</a></p>
        <p>Access Token Hash: <span id="claim-at_hash">{{ .Claims.AccessTokenHash }}</span></p>
        <p>Code Hash: <span id="claim-c_hash">{{ .Claims.CodeHash }}</span></p>
        <p>Authentication Context Class Reference: <span id="claim-acr">{{ .Claims.AuthenticationContextClassReference }}</span></p>
        <p>Authentication Methods Reference: <span id="claim-amr">{{ stringsJoin .Claims.AuthenticationMethodsReference ", " }}</span></p>
        <p>Audience: <span id="claim-aud">{{ stringsJoin .Claims.Audience ", " }}</span></p>
        <p>Expires: <span id="claim-exp">{{ .Claims.Expires }}</span></p>
        <p>Issue Time: <span id="claim-iat">{{ .Claims.IssueTime }}</span></p>
        <p>Requested At: <span id="claim-rat">{{ .Claims.RequestedAt }}</span></p>
        <p>Authorize Time: <span id="claim-auth_at">{{ .Claims.AuthorizeTime }}</span></p>
        <p>Not Before: <span id="claim-nbf">{{ .Claims.NotBefore }}</span></p>
        <p>Issuer: <span id="claim-iss">{{ .Claims.Issuer }}</span></p>
        <p>JWT ID: <span id="claim-jti">{{ .Claims.JWTIdentifier }}</span></p>
        <p>Subject: <span id="claim-sub">{{ .Claims.Subject }}</span></p>
        <p>Preferred Username: <span id="claim-preferred_username">{{ .Claims.PreferredUsername }}</span></p>
        <p>Nonce: <span id="claim-nonce">{{ .Claims.Nonce }}</span></p>
        <p>Email: <span id="claim-email">{{ .Claims.Email }}</span></p>
        <p>Email Verified: <span id="claim-email_verified">{{ .Claims.EmailVerified }}</span></p>
        <p>Groups: <span id="claim-groups">{{ stringsJoin .Groups ", " }}</span></p>
        <p>Name: <span id="claim-name">{{ .Claims.Name }}</span></p>
        <p>Raw: <span id="raw">{{ .RawToken }}</span></p>
        {{- else }}
        <p>Not logged yet...</p> <a id="login-link" href="/login">Log in</a>
        {{- end }}
    </div>
</body>
</html>
