package cloudflare

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configTokenKey = "config/token"

func pathConfigToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/token",
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Token for API calls",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigTokenRead,
			logical.CreateOperation: b.pathConfigTokenWrite,
			logical.UpdateOperation: b.pathConfigTokenWrite,
			logical.DeleteOperation: b.pathConfigTokenDelete,
		},

		ExistenceCheck: b.configTokenExistenceCheck,
	}
}

func (b *backend) configTokenExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.readConfigToken(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func (b *backend) readConfigToken(ctx context.Context, storage logical.Storage) (*rootTokenConfig, error) {
	entry, err := storage.Get(ctx, configTokenKey)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	conf := &rootTokenConfig{}
	if err := entry.DecodeJSON(conf); err != nil {
		return nil, errwrap.Wrapf("error reading nomad access configuration: {{err}}", err)
	}

	return conf, nil
}

func (b *backend) pathConfigTokenRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		return logical.ErrorResponse("configuration does not exist. did you configure 'config/token'?"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":    conf.TokenID,
			"token": conf.Token,
		},
	}, nil
}

func (b *backend) pathConfigTokenWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		conf = &rootTokenConfig{}
	}

	token, ok := data.GetOk("token")
	if !ok {
		return logical.ErrorResponse("Missing 'token' in configuration request"), nil
	}
	conf.Token = token.(string)

	client, err := createClient(conf.Token)
	if err != nil {
		return nil, err
	}

	resp, err := client.VerifyAPIToken(context.TODO())
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("encountered error when verifying token: %s", err)), nil
	}
	if resp.Status != "active" {
		return logical.ErrorResponse(fmt.Sprintf("provided token is not currently active. resp:%#v", resp)), nil
	}

	conf.TokenID = resp.ID

	entry, err := logical.StorageEntryJSON(configTokenKey, conf)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigTokenDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configTokenKey); err != nil {
		return nil, err
	}
	return nil, nil
}

type rootTokenConfig struct {
	Token   string `json:"token"`
	TokenID string `json:"id"`
}

const pathConfigTokenHelpSyn = `
Configure Cloudflare token and options used by vault
`

const pathConfigTokenHelpDesc = `
Will confugre this mount with the token used by Vault for all Cloudflare
operations on this mount. Must be configured with: com.cloudflare.api.token.create.

For instructions on how to get and/or create a cloudflare token see their
documentation at https://developers.cloudflare.com/api/tokens/create. Cloudflare has
a 'create api tokens' default template that can be used.
`
