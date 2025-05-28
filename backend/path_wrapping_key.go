// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	wrappingKey     *rsa.PrivateKey
	wrappingKeyOnce sync.Once
)

const WrappingKeyName = "wrapping-key"

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

func (b *backend) pathEthereumWrappingKeyRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	key, err := getOrCreateWrappingKey()
	if err != nil {
		return nil, err
	}
	pub := key.Public()
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": string(pemBytes),
		},
	}, nil
}

func getOrCreateWrappingKey() (*rsa.PrivateKey, error) {
	var err error
	wrappingKeyOnce.Do(func() {
		wrappingKey, err = rsa.GenerateKey(rand.Reader, 4096)
	})
	return wrappingKey, err
}

const (
	pathWrappingKeyHelpSyn  = "Returns the public key to use for wrapping imported keys"
	pathWrappingKeyHelpDesc = "This path is used to retrieve the RSA-4096 wrapping key " +
		"for wrapping keys that are being imported into transit."
)
