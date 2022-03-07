package main

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetURLs(t *testing.T) {
	var (
		public, redirect *url.URL
		err              error
	)

	public, redirect, err = getURLs("https://app.example.com")

	assert.NoError(t, err)
	require.NotNil(t, public)
	require.NotNil(t, redirect)

	assert.Equal(t, "https://app.example.com/", public.String())
	assert.Equal(t, "https://app.example.com/oauth2/callback", redirect.String())

	public, redirect, err = getURLs("https://app.example.com/")

	assert.NoError(t, err)
	require.NotNil(t, public)
	require.NotNil(t, redirect)

	assert.Equal(t, "https://app.example.com/", public.String())
	assert.Equal(t, "https://app.example.com/oauth2/callback", redirect.String())

	public, redirect, err = getURLs("https://app.example.com:5050/")

	assert.NoError(t, err)
	require.NotNil(t, public)
	require.NotNil(t, redirect)

	assert.Equal(t, "https://app.example.com:5050/", public.String())
	assert.Equal(t, "https://app.example.com:5050/oauth2/callback", redirect.String())

	public, redirect, err = getURLs("app.example.com")

	assert.EqualError(t, err, "scheme must be http or https but it is ''")
	assert.Nil(t, public)
	assert.Nil(t, redirect)
}
