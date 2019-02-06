package credhub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/credhub-cli/credhub/auth"
)

// DefaultAllowedClockSkew is the amount of time before an access token
// will expire that we will fetch a new one.
const DefaultAllowedClockSkew = time.Second * 30

// UAAAuthBuilder provides an auth builder that will pro-actively fetch
// new access tokens *before* they expire, instead of flakily re-trying
// requests when they do (as the built-in credhub one currently does)
func UAAAuthBuilder(clientID, clientSecret string) auth.Builder {
	return func(conf auth.Config) (auth.Strategy, error) {
		authURL, err := conf.AuthURL()
		if err != nil {
			return nil, err
		}
		return &uaaAuthStrategy{
			ClientID:         clientID,
			ClientSecret:     clientSecret,
			HTTPClient:       conf.Client(),
			AuthURL:          authURL,
			AllowedClockSkew: DefaultAllowedClockSkew,
		}, nil
	}
}

type uaaAuthStrategy struct {
	accessToken       string
	accessTokenExpiry time.Time
	mu                sync.Mutex

	ClientID         string
	ClientSecret     string
	AuthURL          string
	HTTPClient       *http.Client
	AllowedClockSkew time.Duration
}

func (a *uaaAuthStrategy) Do(req *http.Request) (*http.Response, error) {
	at, err := a.validToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+at)
	return a.HTTPClient.Do(req)
}

func (a *uaaAuthStrategy) validToken() (string, error) {
	now := time.Now().Add(a.AllowedClockSkew)

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.accessTokenExpiry.After(now) {
		return a.accessToken, nil
	}

	req, err := http.NewRequest(http.MethodPost, a.AuthURL+"/oauth/token", bytes.NewReader([]byte((url.Values{
		"grant_type":    {"client_credentials"},
		"response_type": {"token"},
		"client_id":     {a.ClientID},
		"client_secret": {a.ClientSecret},
	}).Encode())))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	defer io.Copy(ioutil.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad status code back from UAA")
	}

	var t struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&t)
	if err != nil {
		return "", err
	}

	parts := strings.Split(t.AccessToken, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed jwt - expected 3 parts")
	}

	// we don't verify the JWT signature, as we are not making any security decision
	// based on the content. We only care about the expiration field so that we know
	// when to renew this token
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	var mc struct {
		Expiration int64 `json:"exp"`
	}
	err = json.Unmarshal(claims, &mc)
	if err != nil {
		return "", err
	}

	a.accessTokenExpiry = time.Unix(mc.Expiration, 0)
	a.accessToken = t.AccessToken

	return t.AccessToken, nil
}
