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
        {{- if eq .Vars.Type "user" }}
        <p id="message">This is the protected user endpoint</p>
        {{- if stringsEqualFold .Claims.PreferredUsername .Vars.Value }}
        <p id="message-grant">Access Granted. Your username is '<span id="user">{{ .Claims.PreferredUsername }}</span>'.</p>
        <p id="access-granted">1</p>
        <p id="protected-secret">{{ .Vars.ProtectedSecret }}</p>
        {{- else }}
        <p id="grant-message">Access Denied. Requires user '<span id="user">{{ .Vars.Value }}</span>'.</p>
        <p id="access-granted">0</p>
        {{- end }}
        {{- else if eq .Vars.Type "group" }}
        <p id="message">This is the protected group endpoint</p>
        {{- if (isStringInSlice .Vars.Value .Claims.Groups) }}
        <p id="grant-message">Access Granted. You have the group '<span id="group">{{ .Vars.Value }}</span>'.</p>
        <p id="access-granted">1</p>
        <p id="protected-secret">{{ .Vars.ProtectedSecret }}</p>
        {{- else }}
        <p id="grant-message">Access Denied. Requires group '<span id="group">{{ .Vars.Value }}</span>'.</p>
        <p id="access-granted">0</p>
        {{- end }}
        {{- else if eq .Vars.Type "basic" }}
        <p id="message">This is the protected endpoint</p>
        <p id="protected-secret">{{ .Vars.ProtectedSecret }}</p>
        {{- else }}
        <p id="message">This is the protected invalid endpoint</p>
        {{- end }}
    </div>
</body>
</html>
