package auth

//go:generate counterfeiter . ExternalCertSource

// CertificateMap maps key ID to X509 encoded certificates, of which
// we only care about the dates, and the subject public key info.
type CertificateMap map[string][]byte

// ExternalCertSource retrieves the current CertificateMap
type ExternalCertSource interface {
	FetchCurrentCertificates() (CertificateMap, error)
}
