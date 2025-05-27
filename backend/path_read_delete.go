package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathReadAndDelete(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("secret_id") + "?",
		HelpSynopsis: "Create, get or delete an Ethereum account by secret_id",
		HelpDescription: `

    POST - create a new account for the given secret_id
    GET - return the account by the secret_id
    DELETE - deletes the account by the secret_id

    `,
		Fields: map[string]*framework.FieldSchema{
			"secret_id": &framework.FieldSchema{Type: framework.TypeString},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.readAccount,
			logical.DeleteOperation: b.deleteAccount,
		},
	}
}
