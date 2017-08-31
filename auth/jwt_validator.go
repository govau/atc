package auth

import (
	"crypto/rsa"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

type JWTValidator struct {
	PublicKey *rsa.PublicKey

	// Audience (if set) must match the "aud" value in the claim
	Audience string

	// TokenType - empty value is equivalent to "BEARER"
	TokenType string
}

func (validator JWTValidator) IsAuthenticated(r *http.Request) bool {
	token, err := getJWT(r, validator.PublicKey, validator.TokenType)
	if err != nil {
		return false
	}

	if !token.Valid {
		return false
	}

	if validator.Audience != "" {
		mc, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return false
		}

		if !mc.VerifyAudience(validator.Audience, true) {
			return false
		}
	}

	return true
}

func (validator JWTValidator) GetTeam(r *http.Request) (string, bool, bool) {
	token, err := getJWT(r, validator.PublicKey, validator.TokenType)
	if err != nil {
		return "", false, false
	}

	claims := token.Claims.(jwt.MapClaims)
	teamNameInterface, teamNameOK := claims[teamNameClaimKey]
	isAdminInterface, isAdminOK := claims[isAdminClaimKey]

	if !(teamNameOK && isAdminOK) {
		return "", false, false
	}

	teamName := teamNameInterface.(string)
	isAdmin := isAdminInterface.(bool)

	return teamName, isAdmin, true
}

func (validator JWTValidator) GetSystem(r *http.Request) (bool, bool) {
	token, err := getJWT(r, validator.PublicKey, validator.TokenType)
	if err != nil {
		return false, false
	}

	claims := token.Claims.(jwt.MapClaims)
	isSystemInterface, isSystemOK := claims[isSystemKey]
	if !isSystemOK {
		return false, false
	}

	return isSystemInterface.(bool), true
}

func (validator JWTValidator) GetCSRFToken(r *http.Request) (string, bool) {
	token, err := getJWT(r, validator.PublicKey, validator.TokenType)
	if err != nil {
		return "", false
	}

	claims := token.Claims.(jwt.MapClaims)
	csrfToken, ok := claims[csrfTokenClaimKey]
	if !ok {
		return "", false
	}

	return csrfToken.(string), true
}
