package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	errCannotParseHeader = errors.New("unable to parse authorization header")
)

type JWTValidator struct {
	// PublicKeySource used for signature validation
	PublicKeySource VerificationKeySource
}

func (validator JWTValidator) IsAuthenticated(r *http.Request) bool {
	_, err := validator.getJWTClaims(r)
	if err != nil {
		return false
	}

	return true
}

func (jr JWTValidator) GetTeam(r *http.Request) (string, bool, bool) {
	claims, err := jr.getJWTClaims(r)
	if err != nil {
		return "", false, false
	}

	teamNameInterface, teamNameOK := claims[teamNameClaimKey]
	isAdminInterface, isAdminOK := claims[isAdminClaimKey]

	if !(teamNameOK && isAdminOK) {
		return "", false, false
	}

	teamName := teamNameInterface.(string)
	isAdmin := isAdminInterface.(bool)

	return teamName, isAdmin, true
}

func (jr JWTValidator) GetSystem(r *http.Request) (bool, bool) {
	claims, err := jr.getJWTClaims(r)
	if err != nil {
		return false, false
	}

	isSystemInterface, isSystemOK := claims[isSystemKey]
	if !isSystemOK {
		return false, false
	}

	return isSystemInterface.(bool), true
}

func (jr JWTValidator) GetCSRFToken(r *http.Request) (string, bool) {
	claims, err := jr.getJWTClaims(r)
	if err != nil {
		return "", false
	}

	csrfToken, ok := claims[csrfTokenClaimKey]
	if !ok {
		return "", false
	}

	return csrfToken.(string), true
}

// getJWTClaims will look for an appropriate Authorization header in the given request,
// and validate it, then return the validated claims.
func (jr JWTValidator) getJWTClaims(r *http.Request) (jwt.MapClaims, error) {
	fun := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jr.PublicKeySource.FetchVerificationKey(r)
	}

	t, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(t, fun)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("token claims not valid")
	}

	return claims, nil
}

// extractBearerToken finds the bearer token in the request
func extractBearerToken(r *http.Request) (string, error) {
	bits := extractBearerTokenAndType(r)
	if len(bits) != 2 {
		return "", errCannotParseHeader
	}
	return bits[1], nil
}

// extractBearerTokenAndType returns the type of token (might be "") and then if the token (if present)
func extractBearerTokenAndType(r *http.Request) []string {
	return strings.SplitN(r.Header.Get("Authorization"), " ", 2)
}
