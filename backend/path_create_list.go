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
			"secret_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "UUID to identify the Ethereum account",
			},
		},
	}
}
