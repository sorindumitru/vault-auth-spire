package verifier

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type Verifier interface {
	VerifyJWTSVID(token string, audiences []string) (spiffeid.ID, error)
	VerifyX509SVID(clientCert []*x509.Certificate) (spiffeid.ID, error)
}

type LocalTrustBundleVerifier struct {
	trustBundles *spiffebundle.Set
}

func NewLocalTrustBundleVerifier() *LocalTrustBundleVerifier {
	return &LocalTrustBundleVerifier{
		trustBundles: spiffebundle.NewSet(),
	}
}

func (v *LocalTrustBundleVerifier) AddTrustBundle(trustDomainName string, path string) error {
	trustDomain, err := spiffeid.TrustDomainFromString(trustDomainName)
	if err != nil {
		return err
	}

	bundle, err := spiffebundle.Load(trustDomain, path)
	if err != nil {
		return err
	}

	v.trustBundles.Add(bundle)

	return nil
}

func (v *LocalTrustBundleVerifier) VerifyX509SVID(certs []*x509.Certificate) (spiffeid.ID, error) {
	id, _, err := x509svid.Verify(certs, v.trustBundles)
	return id, err
}

func (v *LocalTrustBundleVerifier) VerifyJWTSVID(token string, audiences []string) (spiffeid.ID, error) {
	svid, err := jwtsvid.ParseAndValidate(token, v.trustBundles, audiences)
	if err != nil {
		return spiffeid.ID{}, err
	}

	return svid.ID, nil
}
