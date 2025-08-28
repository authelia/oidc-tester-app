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

    <link rel="stylesheet" href="{{ assetURL "styles.css" }}">

</head>

<body>
    <div id="container">
        <p><a href="/" id="home-link">Home</a></p>
        <p><a id="login-link" href="/login">Log in</a></p>
        <p id="state">{{ .State }}</p>
        <p id="error">{{ .Error }}</p>
        {{- if .ErrorDescription }}
        <p id="error_description">{{ .ErrorDescription }}</p>
        {{- end }}
        {{- if .ErrorURI }}
        <p><a id="error_uri" href="{{ .ErrorURI }}">{{ .ErrorURI }}</a></p>
        {{- end }}
    </div>
</body>
</html>
