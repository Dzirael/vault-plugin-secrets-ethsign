package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathEthereumWrappingKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "wrapping_key",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathEthereumWrappingKeyRead,
		},
		HelpSynopsis:    "Returns the public key to use for wrapping imported keys",
		HelpDescription: "This path is used to retrieve the RSA-4096 wrapping key for wrapping keys that are being imported.",
	}
}

const (
	pathWrappingKeyHelpSyn  = "Returns the public key to use for wrapping imported keys"
	pathWrappingKeyHelpDesc = "This path is used to retrieve the RSA-4096 wrapping key " +
		"for wrapping keys that are being imported into transit."
)
