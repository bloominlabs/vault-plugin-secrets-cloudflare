# Vault Secrets Plugin - Cloudflare

[Vault][vault] secrets plugins to simplying creation, management, and
revocation of [Cloudflare][cloudflare] API tokens.

## Usage

### Setup Endpoint

1. Download and enable plugin locally (TODO)

2. Configure the plugin

   ```
   vault write /cloudflare/config/token token=<token>
   ```

3. Add one or more policies

### Configure Policies

```
# NOTE: this policy will not work and is just an example
vault write /cloudflare/roles/<role-name> policy_document=-<<EOF
[
  {
    "id": "f267e341f3dd4697bd3b9f71dd96247f",
    "effect": "allow",
    "resources": {
      "*": "*"
    },
    "permission_groups": [
      {
        "id": "c8fed203ed3043cba015a93ad1616f1f",
        "name": "Zone Read"
      },
      {
        "id": "82e64a83756745bbbb1c9c2701bf816b",
        "name": "DNS Read"
      }
    ]
  }
]
EOF
```

you can then read from the role using

```
vault read /cloudflare/creds/<role-name>
```

### Rotating the Root Token

The plugin supports rotating the configured admin token to seamlessly improve
security.

To rotate the token, perform a 'write' operation on the
`config/rotate-root` endpoint

```bash
> export VAULT_ADDR="http://localhost:8200"
> vault write -f config/rotate-root
Key      Value
---      -----
name     vault-admin-{timestamp in nano seconds}
```

### Generate a new Token

To generate a new token:

[Create a new cloudflare policy](#configure-policies) and perform a 'read' operation on the `creds/<role-name>` endpoint.

```bash
# To read data using the api
$ vault read cloudflare/role/dns-edit
Key                Value
---                -----
lease_id           cloudflare/creds/test/956Fo9MQgleoqosK5wuMVwPC
lease_duration     768h
lease_renewable    true
id                 9c40db059267e91c7f3f22220c1536ed
token              <token>
```

## Development

The provided [Earthfile] ([think makefile, but using
docker](https://earthly.dev)) is used to build, test, and publish the plugin.
See the build targets for more information. Common targets include

```bash
# build a local version of the plugin
$ earthly +build

# execute integration tests
#
# use https://developers.cloudflare.com/api/tokens/create to create a token
# with 'User:API Tokens:Edit' permissions
$ TEST_CLOUDFLARE_TOKEN=<YOUR_CLOUDFLARE_TOKEN> earthly --secret TEST_CLOUDFLARE_TOKEN +test

# start vault and enable the plugin locally
earthly +dev
```

[vault]: https://www.vaultproject.io/
[cloudflare]: https://www.cloudflare.com/
[earthfile]: ./Earthfile
