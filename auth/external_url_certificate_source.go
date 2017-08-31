package auth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// ExternalURLCertificateSource fetches certificates from the URL specified.
type ExternalURLCertificateSource struct {
	// URL to fetch from
	URL string
}

func (s *ExternalURLCertificateSource) FetchCurrentCertificates() (CertificateMap, error) {
	resp, err := http.Get(s.URL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code")
	}

	var cm CertificateMap
	err = json.NewDecoder(resp.Body).Decode(&cm)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return cm, nil
}
