package main

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

const staticURLPath = "/static/"

func assetURL(u string) string {
	delim := "?v="
	if strings.Contains(u, "?") {
		delim = "&v="
	}

	return staticURLPath + u + delim + version
}

func isStringInSlice(s string, slice []string) bool {
	for _, x := range slice {
		if s == x {
			return true
		}
	}

	return false
}

func filterText(input string, filters []string) (output string) {
	if len(filters) == 0 {
		return input
	}

	for _, filter := range filters {
		input = strings.Replace(input, filter, strings.Repeat("*", len(filter)), -1)
	}

	return input
}

func filterSliceOfText(input []string, filters []string) (output []string) {
	for _, item := range input {
		output = append(output, filterText(item, filters))
	}

	return output
}

func getURLs(rootURL string) (publicURL *url.URL, redirectURL *url.URL, err error) {
	if publicURL, err = url.Parse(rootURL); err != nil {
		return nil, nil, err
	}

	if publicURL.Scheme != "http" && publicURL.Scheme != "https" {
		return nil, nil, fmt.Errorf("scheme must be http or https but it is '%s'", publicURL.Scheme)
	}

	if !strings.HasSuffix(publicURL.Path, "/") {
		publicURL.Path += "/"
	}

	redirectURL = &url.URL{}
	*redirectURL = *publicURL
	redirectURL.Path = path.Join(redirectURL.Path, "/oauth2/callback")

	return publicURL, redirectURL, nil
}
