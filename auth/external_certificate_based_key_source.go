package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// ExternalCertificateBasedKeySource fetches keys from an external provider and validates
// tokens on this basis.
type ExternalCertificateBasedKeySource struct {
	// CertificateSource is where we periodically fetch certificates from
	// The results are cached by this validator.
	CertificateSource ExternalCertSource

	// Audience (if set) will not provide key for verification unless it claims it is intended for us
	Audience string

	// Internal
	keyLock sync.RWMutex
	certMap CertificateMap
}

func (v *ExternalCertificateBasedKeySource) FetchVerificationKey(r *http.Request) (*rsa.PublicKey, error) {
	t, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}

	mc, err := getUnverifiedMapClaims(t)
	if err != nil {
		return nil, err
	}

	keyID, ok := mc["kid"].(string)
	if !ok {
		return nil, errors.New("bad key ID")
	}

	if v.Audience != "" {
		aud, ok := mc["aud"].(string)
		if !ok {
			return nil, errors.New("bad aud")
		}
		if aud != v.Audience {
			return nil, errors.New("token not intended for us")
		}
	}

	pk, err := v.loadCertForKey(keyID)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func (v *ExternalCertificateBasedKeySource) fetchCurrentCerts() error {
	cm, err := v.CertificateSource.FetchCurrentCertificates()
	if err != nil {
		return err
	}

	v.keyLock.Lock()
	v.certMap = cm
	v.keyLock.Unlock()

	return nil
}

func (v *ExternalCertificateBasedKeySource) loadCertForKey(kid string) (*rsa.PublicKey, error) {
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

// getUnverifiedMapClaims returns an unverified field from the JWT. Useful for extracting the KeyID
func getUnverifiedMapClaims(token string) (jwt.MapClaims, error) {
	bits := strings.Split(token, ".")
	if len(bits) != 3 {
		return nil, errors.New("wrong number of bits in jwt")
	}
	seg, err := jwt.DecodeSegment(bits[1])
	if err != nil {
		return nil, err
	}
	var rv jwt.MapClaims
	err = json.Unmarshal(seg, &rv)
	if err != nil {
		return nil, err
	}
	return rv, nil
}
