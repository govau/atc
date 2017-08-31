package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/concourse/atc/auth"
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func requestWithAuthHeader(s string) *http.Request {
	return &http.Request{
		Header: http.Header{
			"Authorization": {s},
		},
	}
}

func mintToken(method jwt.SigningMethod, key interface{}, tt string, expiration time.Time, teamName string, isAdmin bool, csrfToken, audience string) *http.Request {
	mc := jwt.MapClaims{
		"exp":      expiration.Unix(),
		"teamName": teamName,
		"isAdmin":  isAdmin,
		"csrf":     csrfToken,
	}
	if audience != "" {
		mc["aud"] = audience
	}
	jwtToken := jwt.NewWithClaims(method, mc)

	signed, err := jwtToken.SignedString(key)
	Expect(err).NotTo(HaveOccurred())

	return requestWithAuthHeader(fmt.Sprintf("%s %s", tt, signed))
}

var _ = Describe("JwtValidatorTests", func() {
	var (
		key1 *rsa.PrivateKey
		key2 *rsa.PrivateKey

		s1 auth.VerificationKeySource
		s2 auth.VerificationKeySource
	)

	BeforeEach(func() {
		var err error
		key1, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		key2, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		s1 = &auth.StaticKeySource{
			PublicKey: &key1.PublicKey,
		}
		s2 = &auth.StaticKeySource{
			PublicKey: &key2.PublicKey,
		}
	})

	It("works", func() {
		// put these all in one test so that we don't waste time regenerate keys over and over

		By("works normally")
		Expect((&auth.JWTValidator{
			PublicKeySource: s1,
		}).IsAuthenticated(mintToken(
			jwt.SigningMethodRS256,
			key1,
			"Bearer",
			time.Now().Add(time.Hour),
			"foo",
			false,
			"",
			"",
		))).To(BeTrue())

		By("works with wrong case normally")
		Expect((&auth.JWTValidator{
			PublicKeySource: s1,
		}).IsAuthenticated(mintToken(
			jwt.SigningMethodRS256,
			key1,
			"BEARER",
			time.Now().Add(time.Hour),
			"foo",
			false,
			"",
			"",
		))).To(BeTrue())

		By("works with External")
		Expect((&auth.JWTValidator{
			PublicKeySource: s1,
		}).IsAuthenticated(mintToken(
			jwt.SigningMethodRS256,
			key1,
			"exTERNal",
			time.Now().Add(time.Hour),
			"foo",
			false,
			"",
			"",
		))).To(BeTrue())

		By("fails with wrong key")
		Expect((&auth.JWTValidator{
			PublicKeySource: s2,
		}).IsAuthenticated(mintToken(
			jwt.SigningMethodRS256,
			key1,
			"exTERNal",
			time.Now().Add(time.Hour),
			"foo",
			false,
			"",
			"",
		))).To(BeFalse())

		By("fails with none algorithm (common JWT spec bug)")
		Expect((&auth.JWTValidator{
			PublicKeySource: s1,
		}).IsAuthenticated(mintToken(
			jwt.SigningMethodNone,
			jwt.UnsafeAllowNoneSignatureType, // have to try hard to get the library to "sign" with one of these
			"Bearer",
			time.Now().Add(time.Hour),
			"foo",
			false,
			"",
			"",
		))).To(BeFalse())

		By("fails with bad expiry")
		Expect((&auth.JWTValidator{
			PublicKeySource: s1,
		}).IsAuthenticated(mintToken(
			jwt.SigningMethodRS256,
			key1,
			"Bearer",
			time.Now().Add(-time.Hour),
			"foo",
			false,
			"",
			"",
		))).To(BeFalse())
	})
})
