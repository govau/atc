package auth

import (
	"crypto/rsa"
	"net/http"
	"strings"
)

// TokenTypeKeySource will examine the Authorization header and pick a VerificationKeySource based
// on the token type. The type will be lower-cased before being looked up in the map, and as such
// the map must contain lower-case values.
type TokenTypeKeySource struct {
	// Sources keys must be lower case
	Sources map[string]VerificationKeySource
}

func (ttks *TokenTypeKeySource) FetchVerificationKey(r *http.Request) (*rsa.PublicKey, error) {
	ch, ok := ttks.Sources[strings.ToLower(extractBearerTokenAndType(r)[0])]
	if !ok {
		return nil, errCannotParseHeader
	}
	return ch.FetchVerificationKey(r)
}
