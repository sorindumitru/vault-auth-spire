package verifier

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/sirupsen/logrus"
)

type WorkloadAPIVerifier struct {
	bundleSource *workloadapi.BundleSource
}

func NewWorkloadAPIVerifier(endpointSocket string) (*WorkloadAPIVerifier, error) {
	var clientOptions []workloadapi.ClientOption
	clientOptions = append(clientOptions, workloadapi.WithLogger(logrus.New()))
	if endpointSocket != "" {
		clientOptions = append(clientOptions, workloadapi.WithAddr(endpointSocket))
	}
	bundleSource, err := workloadapi.NewBundleSource(context.Background(), workloadapi.WithClientOptions(clientOptions...))
	if err != nil {
		return nil, err
	}
	return &WorkloadAPIVerifier{
		bundleSource,
	}, nil
}

func (v *WorkloadAPIVerifier) VerifyX509SVID(certs []*x509.Certificate) (spiffeid.ID, error) {
	id, _, err := x509svid.Verify(certs, v.bundleSource)
	return id, err
}

func (v *WorkloadAPIVerifier) VerifyJWTSVID(token string, audiences []string) (spiffeid.ID, error) {
	svid, err := jwtsvid.ParseAndValidate(token, v.bundleSource, audiences)
	if err != nil {
		return spiffeid.ID{}, err
	}

	return svid.ID, nil
}
