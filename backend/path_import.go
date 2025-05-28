package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathEthereumImport(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "import",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.ethereumImport,
		},
		HelpSynopsis:    "Import EVM private key, encrypted with Vault public key",
		HelpDescription: "Imports a private key, decrypts it inside Vault and returns the address.",
		Fields: map[string]*framework.FieldSchema{
			"secret_id": {
				Type:        framework.TypeString,
				Description: "UUID for account identification",
			},
			"wrapped_private_key": {
				Type:        framework.TypeString,
				Description: "Wrapped private key (base64)",
			},
		},
	}
}
