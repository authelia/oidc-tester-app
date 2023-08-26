package main

import (
	"embed"
	"fmt"
	"html/template"
	"strings"
)

//go:embed templates/*
var templateFS embed.FS

var (
	indexTpl, protectedTpl, errorTpl *template.Template

	templateFuncMap = template.FuncMap{
		"stringsJoin":      strings.Join,
		"stringsEqualFold": strings.EqualFold,
		"isStringInSlice":  isStringInSlice,
	}
)

type indexTplData struct {
	Title, Description, RawToken string

	Error    string
	LoggedIn bool
	Claims   Claims
	Groups   []string
}

type protectedTplData struct {
	Title, Description string
	Vars               struct {
		Type, Value, ProtectedSecret string
	}
	Claims           Claims
	AuthorizeCodeURL string
}

type errorTplData struct {
	Title, Description string

	Error, ErrorDescription, ErrorURI, State string
}

func init() {
	indexTpl = templateMustLoadAndParse("index")
	protectedTpl = templateMustLoadAndParse("protected")
	errorTpl = templateMustLoadAndParse("error")
}

func templateMustLoadAndParse(name string) *template.Template {
	if data, err := templateFS.ReadFile(fmt.Sprintf("templates/%s.tpl", name)); err != nil {
		panic(err)
	} else {
		t, err := template.New(name).Funcs(templateFuncMap).Parse(string(data))
		if err != nil {
			panic(err)
		}

		return t
	}

	return nil
}
