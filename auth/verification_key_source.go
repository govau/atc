package auth

import (
	"crypto/rsa"
	"net/http"
)

type VerificationKeySource interface {
	FetchVerificationKey(r *http.Request) (*rsa.PublicKey, error)
}
