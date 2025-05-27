package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateAndList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation:   b.listAccounts,
			logical.UpdateOperation: b.createAccount,
		},
		HelpSynopsis: "List all the Ethereum accounts maintained by the plugin backend and create new accounts.",
		HelpDescription: `

    LIST - list all accounts
    POST - create a new account

    `,
		Fields: map[string]*framework.FieldSchema{
			"privateKey": {
				Type:        framework.TypeString,
				Description: "Hexidecimal string for the private key (32-byte or 64-char long). If present, the request will import the given key instead of generating a new key.",
				Default:     "",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the Ethereum account.",
			},
		},
	}
}
