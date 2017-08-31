package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/concourse/atc/auth/authfakes"

	"github.com/concourse/atc/auth"
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func mintExternalToken(key interface{}, tt string, mc jwt.MapClaims) *http.Request {
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, mc).SignedString(key)
	Expect(err).NotTo(HaveOccurred())

	return &http.Request{
		Header: http.Header{
			"Authorization": {fmt.Sprintf("%s %s", tt, signed)},
		},
	}
}

var _ = Describe("External Validator Tests", func() {
	var (
		key1, key2 *rsa.PrivateKey
		pub1, pub2 *rsa.PublicKey
		kid1, kid2 string
		certMap    auth.CertificateMap
	)

	BeforeEach(func() {
		var err error

		key1, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
		key2, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())

		now := time.Now()

		cert1 := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			PublicKey:    &key1.PublicKey,
			NotAfter:     now.Add(-1 * time.Hour),
			NotBefore:    now.Add(-10 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		cert2 := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			PublicKey:    &key2.PublicKey,
			NotAfter:     now.Add(1 * time.Hour),
			NotBefore:    now.Add(-1 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}

		cert1Bytes, err := x509.CreateCertificate(rand.Reader, cert1, cert1, &key1.PublicKey, key1)
		Expect(err).ToNot(HaveOccurred())
		cert2Bytes, err := x509.CreateCertificate(rand.Reader, cert2, cert2, &key2.PublicKey, key2)
		Expect(err).ToNot(HaveOccurred())

		cert1, err = x509.ParseCertificate(cert1Bytes)
		Expect(err).ToNot(HaveOccurred())
		cert2, err = x509.ParseCertificate(cert2Bytes)
		Expect(err).ToNot(HaveOccurred())

		spkiHash1 := sha256.Sum256(cert1.RawSubjectPublicKeyInfo)
		spkiHash2 := sha256.Sum256(cert2.RawSubjectPublicKeyInfo)

		kid1 = hex.EncodeToString(spkiHash1[:])
		kid2 = hex.EncodeToString(spkiHash2[:])

		certMap = auth.CertificateMap{
			kid1: cert1Bytes,
			kid2: cert2Bytes,
		}

		pub1 = &key1.PublicKey
		pub2 = &key2.PublicKey
	})

	It("works", func() {
		// Do all in one It so that we don't waste CPU generate private keys over and over
		var pubKey *rsa.PublicKey
		var err error

		By("normally")
		pubKey, err = (&auth.ExternalCertificateBasedKeySource{
			CertificateSource: &authfakes.FakeExternalCertSource{
				FetchCurrentCertificatesStub: func() (auth.CertificateMap, error) {
					return certMap, nil
				},
			},
			Audience: "foo",
		}).FetchVerificationKey(mintExternalToken(
			key2,
			auth.TokenTypeExternal,
			jwt.MapClaims{
				"aud": "foo",
				"kid": kid2,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
		))
		Expect(err).NotTo(HaveOccurred())
		Expect(pubKey).To(Equal(pub2))

		By("fails with expired key")
		pubKey, err = (&auth.ExternalCertificateBasedKeySource{
			CertificateSource: &authfakes.FakeExternalCertSource{
				FetchCurrentCertificatesStub: func() (auth.CertificateMap, error) {
					return certMap, nil
				},
			},
			Audience: "foo",
		}).FetchVerificationKey(mintExternalToken(
			key2,
			auth.TokenTypeExternal,
			jwt.MapClaims{
				"aud": "foo",
				"kid": kid1,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
		))
		Expect(err).To(HaveOccurred())

		By("fails with wrong audience")
		pubKey, err = (&auth.ExternalCertificateBasedKeySource{
			CertificateSource: &authfakes.FakeExternalCertSource{
				FetchCurrentCertificatesStub: func() (auth.CertificateMap, error) {
					return certMap, nil
				},
			},
			Audience: "foo",
		}).FetchVerificationKey(mintExternalToken(
			key2,
			auth.TokenTypeExternal,
			jwt.MapClaims{
				"aud": "bar",
				"kid": kid2,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
		))
		Expect(err).To(HaveOccurred())

		By("fails with unknown key")
		pubKey, err = (&auth.ExternalCertificateBasedKeySource{
			CertificateSource: &authfakes.FakeExternalCertSource{
				FetchCurrentCertificatesStub: func() (auth.CertificateMap, error) {
					return certMap, nil
				},
			},
			Audience: "foo",
		}).FetchVerificationKey(mintExternalToken(
			key2,
			auth.TokenTypeExternal,
			jwt.MapClaims{
				"aud": "foo",
				"kid": "wrongkey",
				"exp": time.Now().Add(time.Minute).Unix(),
			},
		))
		Expect(err).To(HaveOccurred())

		By("fail no audience")
		pubKey, err = (&auth.ExternalCertificateBasedKeySource{
			CertificateSource: &authfakes.FakeExternalCertSource{
				FetchCurrentCertificatesStub: func() (auth.CertificateMap, error) {
					return certMap, nil
				},
			},
			Audience: "foo",
		}).FetchVerificationKey(mintExternalToken(
			key2,
			auth.TokenTypeExternal,
			jwt.MapClaims{
				"kid": kid2,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
		))
		Expect(err).To(HaveOccurred())
	})
})
