package verifier

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type Verifier interface {
	VerifyJWTSVID(token string, audiences []string) (spiffeid.ID, error)
	VerifyX509SVID(clientCert []*x509.Certificate) (spiffeid.ID, error)
}
