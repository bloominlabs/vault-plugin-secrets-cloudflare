package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// maxTokenNameLength is the maximum length for the name of a Nomad access
// token
const maxTokenNameLength = 120

func createTokenName(role string) string {
	lowerRole := strings.ToLower(role)

	tokenName := fmt.Sprintf("vault-%s-%d", lowerRole, time.Now().UnixNano())

	// Note: if the given role name is sufficiently long, the UnixNano() portion
	// of the pseudo randomized token name is the part that gets trimmed off,
	// weakening it's randomness.
	if len(tokenName) > maxTokenNameLength {
		tokenName = tokenName[:maxTokenNameLength]
	}

	return tokenName
}

func pathCredsCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Create a cloudflare token from a Vault role",
			},
			"condition": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "JSON-encoded cloudflare IP constraints to apply to the token. Useful for limiting token usage to the IP of a service. See https://api.cloudflare.com/#user-api-tokens-create-token for more information.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	condition := cloudflare.APITokenCondition{}
	policies := []cloudflare.APITokenPolicies{}
	role := d.Get("role").(string)

	if _, ok := d.GetOk("condition"); ok {
		conditionRaw := d.Get("condition").(string)
		if len(conditionRaw) > 0 {
			err := json.Unmarshal([]byte(conditionRaw), &condition)

			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("err while decoding 'condition'. err: %s", err)), nil
			}
		}
	}

	roleEntry, err := b.roleRead(ctx, req.Storage, role)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("err while getting role configuration for '%s'. err: %s", role, err)), nil
	}
	if roleEntry == nil {
		return logical.ErrorResponse(fmt.Sprintf("could not find entry for role '%s', did you configure it?", role)), nil
	}

	if roleEntry.PolicyDocument != "" {
		err = json.Unmarshal([]byte(roleEntry.PolicyDocument), &policies)
		if err != nil {
			return logical.ErrorResponse("failed to marshal '%s' into a list of cloudflare policies. ensure your configuration is correct", roleEntry.PolicyDocument), nil
		}
	}

	// Get the http client
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	lease, err := b.LeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	ttl, _, err := framework.CalculateTTL(b.System(), 0, lease.TTL, 0, lease.MaxTTL, 0, time.Time{})
	if err != nil {
		return logical.ErrorResponse("failed to caluclate ttl. err: %s", err), nil
	}

	var expirationDate time.Time = time.Now().UTC().Add(ttl).Truncate(time.Second)
	token := cloudflare.APIToken{
		Name:      createTokenName(role),
		Policies:  policies,
		Condition: &condition,
		ExpiresOn: &expirationDate,
	}

	createdToken, err := c.CreateAPIToken(ctx, token)
	if err != nil {
		return logical.ErrorResponse("failed to create token. err: %s", err), nil
	}

	// Use the helper to create the secret
	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"id":    createdToken.ID,
		"token": createdToken.Value,
	}, map[string]interface{}{
		"id":    createdToken.ID,
		"token": createdToken.Value,
	})
	resp.Secret.TTL = lease.TTL
	resp.Secret.MaxTTL = lease.MaxTTL
	return resp, nil
}
