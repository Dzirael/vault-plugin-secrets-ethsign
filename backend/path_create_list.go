package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListAccounts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "accounts",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			//logical.UpdateOperation: b.createAccount,
			logical.ListOperation: b.listAccounts,
		},
		HelpSynopsis:    "List all accounts",
		HelpDescription: ` LIST - list all accounts`,
	}
}
