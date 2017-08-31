package auth

import (
	"crypto/rsa"
	"net/http"
)

// StaticKeySource returns the public key
type StaticKeySource struct {
	// PublicKey to return
	PublicKey *rsa.PublicKey
}

func (s *StaticKeySource) FetchVerificationKey(r *http.Request) (*rsa.PublicKey, error) {
	return s.PublicKey, nil
}
