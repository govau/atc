package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/concourse/atc/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MultiJwtTest", func() {
	var (
		multi      auth.VerificationKeySource
		kInt, kExt *rsa.PublicKey
	)

	BeforeEach(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		kInt = &k.PublicKey

		k, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		kExt = &k.PublicKey

		multi = &auth.TokenTypeKeySource{
			Sources: map[string]auth.VerificationKeySource{
				strings.ToLower(auth.TokenTypeExternal): &auth.StaticKeySource{
					PublicKey: kExt,
				},
				strings.ToLower(auth.TokenTypeBearer): &auth.StaticKeySource{
					PublicKey: kInt,
				},
			},
		}
	})

	Context("test multi jwt selection", func() {
		It("gets external", func() {
			k, err := multi.FetchVerificationKey(requestWithAuthHeader("External token"))
			Expect(err).NotTo(HaveOccurred())
			Expect(k).To(Equal(kExt))
		})
		It("gets external with wrong casing", func() {
			k, err := multi.FetchVerificationKey(requestWithAuthHeader("eXtErNaL"))
			Expect(err).NotTo(HaveOccurred())
			Expect(k).To(Equal(kExt))
		})
		It("works with Bearer", func() {
			k, err := multi.FetchVerificationKey(requestWithAuthHeader("Bearer"))
			Expect(err).NotTo(HaveOccurred())
			Expect(k).To(Equal(kInt))
		})
		It("no header throws error", func() {
			_, err := multi.FetchVerificationKey(&http.Request{})
			Expect(err).To(HaveOccurred())
		})
		It("bogus is error", func() {
			_, err := multi.FetchVerificationKey(requestWithAuthHeader("Bogus foo"))
			Expect(err).To(HaveOccurred())
		})
	})
})
