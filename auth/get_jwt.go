package auth

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

const (
	tokenTypeBearer   = "BEARER"
	tokenTypeExternal = "EXTERNAL"
)

// getUnverifiedField returns an unverified field from the JWT. Useful for extracting the KeyID
func getUnverifiedField(token, field string) (interface{}, error) {
	bits := strings.Split(token, ".")
	if len(bits) != 3 {
		return nil, errors.New("wrong number of bits in jwt")
	}
	seg, err := jwt.DecodeSegment(bits[1])
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	err = json.NewDecoder(bytes.NewReader(seg)).Decode(&m)
	if err != nil {
		return nil, err
	}
	rv, ok := m[field]
	if !ok {
		return nil, errors.New("no such field")
	}
	return rv, nil
}

// getBearerToken finds the bearer token in the request
func getBearerToken(r *http.Request, tokenType string) (string, error) {
	if ah := r.Header.Get("Authorization"); ah != "" {
		// Default type to bearer
		if tokenType == "" {
			tokenType = tokenTypeBearer
		}
		// Should be a bearer token
		l := len(tokenType)
		if len(ah) > l && strings.ToUpper(ah[0:l]) == tokenType {
			return ah[l+1:], nil
		}
	}

	return "", errors.New("unable to parse authorization header")
}

func getJWT(r *http.Request, publicKey *rsa.PublicKey, tokenType string) (token *jwt.Token, err error) {
	t, err := getBearerToken(r, tokenType)
	if err != nil {
		return nil, err
	}
	return jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
}
