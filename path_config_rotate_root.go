package cloudflare

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfigRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateRootUpdate,
			},
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// have to get the client config first because that takes out a read lock
	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}

	tokenConfig, err := req.Storage.Get(ctx, configTokenKey)
	if err != nil {
		return nil, err
	}
	if tokenConfig == nil {
		return nil, fmt.Errorf("no configuration found for config/token")
	}
	var config rootTokenConfig
	if err := tokenConfig.DecodeJSON(&config); err != nil {
		return nil, errwrap.Wrapf("error reading root configuration: {{err}}", err)
	}

	if config.Token == "" {
		return logical.ErrorResponse("Cannot call config/rotate-root when token is empty"), nil
	}

	newTokenValue, err := client.RollAPIToken(context.TODO(), config.TokenID)

	config.Token = newTokenValue

	newEntry, err := logical.StorageEntryJSON(configTokenKey, config)
	if err != nil {
		return nil, errwrap.Wrapf("error generating new config/root JSON: {{err}}", err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, errwrap.Wrapf("error saving new config/root: {{err}}", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id": config.TokenID,
		},
	}, nil
}

const pathConfigRotateRootHelpSyn = `
Request to rotate the root cloudflare token used by Vault
`

const pathConfigRotateRootHelpDesc = `
This path attempts to rotate the cloudflare credentials used by Vault for
this mount. It is only valid if Vault has been configured to use cloudflare
token via the config/token endpoint.`
