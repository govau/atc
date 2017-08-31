package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/concourse/atc"
	"github.com/concourse/atc/db"
	cffly "github.com/govau/cf-fly"
)

type ValidatingUserContextReader interface {
	Validator
	UserContextReader
}

func NewExternalJWTValidator(url, clientID, clientSecret string, fallback ValidatingUserContextReader, tf db.TeamFactory) (ValidatingUserContextReader, error) {
	return &externalJWTValidator{
		Fallback:     fallback,
		URL:          url,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Teams:        tf,
	}, nil
}

type externalJWTValidator struct {
	Fallback     ValidatingUserContextReader
	URL          string
	ClientID     string
	ClientSecret string
	Teams        db.TeamFactory

	keyLock sync.RWMutex
	certMap cffly.CertificateMap
}

func (v *externalJWTValidator) fetchCurrentCerts() error {
	resp, err := http.Get(v.URL + "/v1/keys")
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("bad status code")
	}

	var cm cffly.CertificateMap
	err = json.NewDecoder(resp.Body).Decode(&cm)
	resp.Body.Close()
	if err != nil {
		return err
	}

	v.keyLock.Lock()
	v.certMap = cm
	v.keyLock.Unlock()

	return nil
}

func (v *externalJWTValidator) loadCertForKey(kid string) (*rsa.PublicKey, error) {
	// Try it
	v.keyLock.RLock()
	rv := v.certMap[kid]
	v.keyLock.RUnlock()

	// Then try to fetch once
	if rv == nil {
		err := v.fetchCurrentCerts()
		if err != nil {
			return nil, err
		}
		// Look again
		v.keyLock.RLock()
		rv = v.certMap[kid]
		v.keyLock.RUnlock()
	}

	if rv == nil {
		return nil, errors.New("no cert found")
	}

	cert, err := x509.ParseCertificate(rv)
	if err != nil {
		return nil, err
	}

	// We don't validate the cert (it's self-signed anyway)
	// but we do check the dates etc.

	now := time.Now()
	if now.After(cert.NotAfter) {
		return nil, errors.New("cert expired")
	}
	if now.Before(cert.NotBefore) {
		return nil, errors.New("cert from the future")
	}

	rsaPK, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not rsa public key")
	}

	// TODO: don't allow a token TTL past the cert NVA
	return rsaPK, nil
}

// will return fallback on error
func (v *externalJWTValidator) getPKValidator(r *http.Request) (ValidatingUserContextReader, error) {
	t, err := getBearerToken(r, tokenTypeExternal)
	if err != nil {
		return nil, err
	}

	keyIDO, err := getUnverifiedField(t, "kid")
	if err != nil {
		return nil, err
	}

	keyID, ok := keyIDO.(string)
	if !ok {
		return nil, errors.New("bad key ID")
	}

	pk, err := v.loadCertForKey(keyID)
	if err != nil {
		return nil, err
	}

	return &JWTValidator{
		PublicKey: pk,
		Audience:  v.ClientID,
		TokenType: tokenTypeExternal,
	}, nil
}

func (v *externalJWTValidator) createTeamIfNeeded(verifiedToken string) error {
	shouldCreate, err := getUnverifiedField(verifiedToken, "createIfNotExist")
	if err != nil {
		return nil
	}

	shouldCreateBool, ok := shouldCreate.(bool)
	if !ok {
		return nil
	}

	if !shouldCreateBool {
		return nil
	}

	nameO, err := getUnverifiedField(verifiedToken, "teamName")
	if err != nil {
		return err
	}
	name, ok := nameO.(string)
	if !ok {
		return errors.New("bad team name")
	}

	_, found, err := v.Teams.FindTeam(name)
	if err != nil {
		return err
	}

	if found {
		return nil
	}

	authConfig, err := json.Marshal(&ExternalAuthConfig{
		DisplayName:  "CloudFoundry",
		URL:          v.URL,
		ClientID:     v.ClientID,
		ClientSecret: v.ClientSecret,
	})
	if err != nil {
		return err
	}
	jrm := json.RawMessage(authConfig)

	_, err = v.Teams.CreateTeam(atc.Team{
		Name: name,
		Auth: map[string]*json.RawMessage{
			externalProviderName: &jrm,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

// IsAuthenticated has side-effect of creating team if JWT says to
func (v *externalJWTValidator) IsAuthenticated(r *http.Request) bool {
	ext, err := v.getPKValidator(r)
	if err != nil {
		return v.Fallback.IsAuthenticated(r)
	}
	if !ext.IsAuthenticated(r) {
		return false
	}
	t, err := getBearerToken(r, tokenTypeExternal)
	if err != nil {
		return false
	}
	err = v.createTeamIfNeeded(t)
	if err != nil {
		return false
	}
	return true
}

func (v *externalJWTValidator) GetTeam(r *http.Request) (string, bool, bool) {
	ext, err := v.getPKValidator(r)
	if err != nil {
		return v.Fallback.GetTeam(r)
	}
	return ext.GetTeam(r)
}

func (v *externalJWTValidator) GetSystem(r *http.Request) (bool, bool) {
	ext, err := v.getPKValidator(r)
	if err != nil {
		return v.Fallback.GetSystem(r)
	}
	return ext.GetSystem(r)
}

func (v *externalJWTValidator) GetCSRFToken(r *http.Request) (string, bool) {
	ext, err := v.getPKValidator(r)
	if err != nil {
		return v.Fallback.GetCSRFToken(r)
	}
	return ext.GetCSRFToken(r)
}
