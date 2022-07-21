/** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"vault-auth-spire/internal/common"
	"vault-auth-spire/internal/verifier"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	standardVaultPluginInit()
}

func standardVaultPluginInit() {

	// This is all standard Vault auth plugin initialization stuff

	// Standard args that are passed into every plugin
	apiClientMeta := &api.PluginAPIClientMeta{}
	apiStandardFlags := apiClientMeta.FlagSet()
	apiStandardFlags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: BackendFactory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logrus.Fatal(err)
	}
}

// BackendFactory creates the plugin backend and configures how login requests are handled. If there is
// a failure in properly setting up the plugin then BackendFactory returns an error detailing what the
// failure is. This error is printed to Vault's standard log, and not the log configured for this
// specific plugin.
//
// The plugin requires a single CLI argument when started (which is provided to Vault when registering
// the plugin and passed to the plugin when started by Vault) called `settings-file` which is the
// absolute path to a valid file containing plugin settings. Inability to find or read this file will
// result in failure of the plugin to start. Details about that settings file requirements are described
// elsewhere in this package.
func BackendFactory(ctx context.Context, backendConfig *logical.BackendConfig) (logical.Backend, error) {

	settings, err := parseSettings()
	if nil != err {
		return nil, err
	}

	if err := common.InitializeLogger(settings); err != nil {
		return nil, errors.New("vault-auth-spire: Failed to initialize logging - " + err.Error())
	}

	var spirePlugin spirePlugin
	spirePlugin.settings = settings
	spirePlugin.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   spirePlugin.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"role": {
						Type:        framework.TypeString,
						Description: "The role against which to login",
						Required:    false,
					},
					"jwt-svid": {
						Type:        framework.TypeString,
						Description: "The SPIFFE token to validate",
						Required:    false,
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: spirePlugin.pathLogin,
						Summary:  "Login via Spiffe/Spire SVID",
					},
				},
			},
			pathRole(&spirePlugin),
		},
	}

	if settings.SourceOfTrust.File != nil {
		verifier := verifier.NewLocalTrustBundleVerifier()

		for trustDomain, bundles := range settings.SourceOfTrust.File.Domains {
			for _, bundle := range bundles {
				verifier.AddTrustBundle(trustDomain, bundle)
			}
		}

		spirePlugin.verifier = verifier
	} else if settings.SourceOfTrust.WorkloadAPI != nil {
		verifier, err := verifier.NewWorkloadAPIVerifier(settings.SourceOfTrust.WorkloadAPI.EndpointSocket)
		if err != nil {
			return nil, err
		}
		spirePlugin.verifier = verifier
	} else {
		return nil, errors.New("vault-auth-spire: No verifier found in settings")
	}

	// Calls standard Vault plugin setup - magic happens here I bet :shrugs: but if it fails then we're gonna
	// kill the plugin
	if err := spirePlugin.Setup(ctx, backendConfig); err != nil {
		return nil, errors.New("vault-auth-spire: Failed in call to spirePlugin.Setup(ctx, backendConfig) - " + err.Error())
	}

	return spirePlugin, nil
}

// parseSettings uses the expected `settings-file` CLI argument to load a file containing settings for this plugin.
func parseSettings() (*common.Settings, error) {
	var settingsFilePath string

	// Arguments specific to vault-auth-plugin
	settingsFlags := flag.NewFlagSet("vault-auth-spire flags", flag.ContinueOnError)
	settingsFlags.StringVar(&settingsFilePath, "settings-file", "", "Path to plugin settings")
	settingsFlags.Parse(os.Args[1:])

	if settings, err := common.ReadSettings(settingsFilePath); err != nil {
		return nil, errors.New("vault-auth-spire: Failed to read settings from '" + settingsFilePath + "' - " + err.Error())
	} else {
		return settings, nil
	}
}

// spirePlugin is-a framework.Backend as per the embedded unnamed anon field
type spirePlugin struct {
	*framework.Backend
	settings *common.Settings

	verifier verifier.Verifier
}

// pathLogin is called when something attempts to login to Vault using this plugin's method (ie, spire). A login request
// requires an SVID argument (of type string) containing a valid SVID that can verified as per the plugin's settings. If the
// SVID is verified then the contained SpiffeId will be used as the identifying piece of information about the user
func (spirePlugin *spirePlugin) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	role, err := spirePlugin.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q could not be found", roleName), nil
	}

	var spiffeID spiffeid.ID
	if len(req.Connection.ConnState.PeerCertificates) != 0 {
		spiffeID, err = spirePlugin.verifier.VerifyX509SVID(req.Connection.ConnState.PeerCertificates)
		if err != nil {
			return nil, logical.ErrPermissionDenied
		}
	} else {
		token, ok, err := d.GetOkErr("jwt-svid")
		if !ok {
			return logical.ErrorResponse(fmt.Errorf("Bad or missing 'jwt-svid' request field: %w", err).Error()), nil
		}

		spiffeID, err = spirePlugin.verifier.VerifyJWTSVID(token.(string), []string{"vault"})
		if err != nil {
			return nil, logical.ErrPermissionDenied
		}
	}

	logrus.WithField("spiffeids", role.BoundSPIFFEIDs).Error("The IDS")
	if !role.allowsSPIFFEID(spiffeID) {
		return nil, logical.ErrPermissionDenied
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{},
			Policies: []string{
				"spiffe-policy",
			},
			Metadata: map[string]string{},
			LeaseOptions: logical.LeaseOptions{
				Renewable: false,
			},
		},
	}, nil
}

func (spirePlugin *spirePlugin) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// TODO
	return nil, nil
}

func pathRole(spirePlugin *spirePlugin) *framework.Path {
	p := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
			},
			"bound_spiffe_ids": {
				Type:        framework.TypeCommaStringSlice,
				Description: `The SPIFFE-IDs that are valid for login.`,
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: `Comma-separated list of 'aud' claims that are valid for login; any match is sufficient`,
			},
		},
		ExistenceCheck: spirePlugin.pathRoleExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: spirePlugin.pathRoleRead,
				Summary:  "Read a role",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback: spirePlugin.pathRoleCreateUpdate,
			},

			logical.CreateOperation: &framework.PathOperation{
				Callback: spirePlugin.pathRoleCreateUpdate,
			},

			logical.DeleteOperation: &framework.PathOperation{
				Callback: spirePlugin.pathRoleDelete,
			},
		},
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

type spiffeRole struct {
	tokenutil.TokenParams

	// Role binding properties
	BoundSPIFFEIDs []string `json:"bound_spiffe_ids"`
	BoundAudiences []string `json:"bound_audiences"`
}

func (role *spiffeRole) allowsSPIFFEID(spiffeID spiffeid.ID) bool {
	for _, roleID := range role.BoundSPIFFEIDs {
		logrus.WithField("roleID", roleID).WithField("spiffeid", spiffeID.String()).Error("The IDS")
		if roleID == spiffeID.String() {
			return true
		}
	}

	return false
}

func (spirePlugin *spirePlugin) role(ctx context.Context, s logical.Storage, name string) (*spiffeRole, error) {
	raw, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := new(spiffeRole)
	if err := raw.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

func (spirePlugin *spirePlugin) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := spirePlugin.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (spirePlugin *spirePlugin) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := spirePlugin.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// Create a map of data to be returned
	d := map[string]interface{}{
		"bound_audiences":  role.BoundAudiences,
		"bound_spiffe_ids": role.BoundSPIFFEIDs,
	}

	role.PopulateTokenData(d)

	return &logical.Response{
		Data: d,
	}, nil
}

func (spirePlugin *spirePlugin) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name required"), nil
	}

	// Delete the role itself
	if err := req.Storage.Delete(ctx, "role/"+roleName); err != nil {
		return nil, err
	}

	return nil, nil
}

func (spirePlugin *spirePlugin) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// Check if the role already exists
	role, err := spirePlugin.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = new(spiffeRole)
	}

	if err := role.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if boundAudiences, ok := data.GetOk("bound_audiences"); ok {
		role.BoundAudiences = boundAudiences.([]string)
	}

	if boundSPIFFEIDs, ok := data.GetOk("bound_spiffe_ids"); ok {
		role.BoundSPIFFEIDs = boundSPIFFEIDs.([]string)
	}

	resp := &logical.Response{}
	if role.TokenMaxTTL > spirePlugin.System().MaxLeaseTTL() {
		resp.AddWarning("token max ttl is greater than the system or backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	// Store the entry.
	entry, err := logical.StorageEntryJSON("role/"+roleName, role)
	if err != nil {
		return nil, err
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if len(resp.Warnings) == 0 {
		return nil, nil
	}

	return resp, nil
}
