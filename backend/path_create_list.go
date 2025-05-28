package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateAndRead(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("secret_id"),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.createAccount,
			logical.ListOperation:   b.listAccounts,
		},
		HelpSynopsis: "Create or read a new account with UUID as identifier",
		HelpDescription: `

    POST - create or read a new account with UUID as identifier
	LIST - list all accounts

    `,
		Fields: map[string]*framework.FieldSchema{
			"secret_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "UUID to identify the Ethereum account",
			},
		},
	}
}
