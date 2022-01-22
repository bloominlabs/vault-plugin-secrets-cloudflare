package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	SecretTokenType = "token"
)

func secretToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "cloudflare API token",
			},
			"id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ID of the API Token",
			},
		},

		Renew:  b.secretTokenRenew,
		Revoke: b.secretTokenRevoke,
	}
}

func (b *backend) secretTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("error getting cloudflare client")
	}

	lease, err := b.LeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	id, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, fmt.Errorf("id is missing on the lease")
	}

	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, lease.TTL, 0, lease.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return logical.ErrorResponse("failed to caluclate ttl. err: %s", err), nil
	}

	// Adding a small buffer since the TTL will be calculated again after this
	// call to ensure the credential do not expire before the lease
	expirationDate := time.Now().UTC().Truncate(time.Second)
	if ttl > 0 {
		expirationDate = expirationDate.Add(ttl).Add(time.Minute * 1)
	}
	updatedAPIToken := cloudflare.APIToken{ExpiresOn: &expirationDate}

	_, err = c.UpdateAPIToken(ctx, id.(string), updatedAPIToken)
	if err != nil {
		return logical.ErrorResponse("failed to update token with new expiration date. err: %s", err), nil
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = lease.TTL
	resp.Secret.MaxTTL = lease.MaxTTL
	return resp, nil
}

func (b *backend) secretTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("error getting cloudflare client")
	}

	id, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, fmt.Errorf("id is missing on the lease")
	}

	b.Logger().Info(fmt.Sprintf("Revoking cloudflare token (%s)...", id))
	err = c.DeleteAPIToken(ctx, id.(string))
	if err != nil {
		var responseError *cloudflare.APIRequestError
		// If cloudflare returns 404 that means the token is already deleted
		if errors.As(err, &responseError) && responseError.HTTPStatusCode() == http.StatusNotFound {
			return nil, nil
		}
		return logical.ErrorResponse(fmt.Sprintf("failed to revoke cloudflare token (%s). err: %s", id, err)), nil
	}

	return nil, nil
}
