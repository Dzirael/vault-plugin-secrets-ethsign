package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathExport(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:      "export/accounts/" + framework.GenericNameRegex("secret_id"),
		HelpSynopsis: "Export an Ethereum account",
		HelpDescription: `
		
    GET - return the account by the secret_id with the private key

    `,
		Fields: map[string]*framework.FieldSchema{
			"secret_id": &framework.FieldSchema{Type: framework.TypeString},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.exportAccount,
		},
	}
}
