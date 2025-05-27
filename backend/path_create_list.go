package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateAndList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("secret_id"),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation:   b.listAccounts,
			logical.UpdateOperation: b.createAccount,
		},
		HelpSynopsis: "List all the Ethereum accounts maintained by the plugin backend and create new accounts.",
		HelpDescription: `

    LIST - list all accounts
    POST - create a new account with UUID as identifier

    `,
		Fields: map[string]*framework.FieldSchema{
			"privateKey": {
				Type:        framework.TypeString,
				Description: "Hexidecimal string for the private key (32-byte or 64-char long). If present, the request will import the given key instead of generating a new key.",
				Default:     "",
			},
			"secret_id": {
				Type:        framework.TypeString,
				Description: "UUID to identify the Ethereum account. If not provided, a new UUID will be generated.",
			},
		},
	}
}
