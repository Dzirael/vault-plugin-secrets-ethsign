package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/tink/go/kwp/subtle"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathEthereumImport(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "import",
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
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.ethereumImport,
		},
		HelpSynopsis:    "Import EVM private key, encrypted with Vault public key",
		HelpDescription: "Imports a private key, decrypts it inside Vault and returns the address.",
	}
}

func (b *backend) ethereumImport(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretIDStr := data.Get("secret_id").(string)
	if secretIDStr == "" {
		return nil, errors.New("secret_id is required")
	}
	_, err := uuid.Parse(secretIDStr)
	if err != nil {
		return nil, errors.New("invalid secret_id format")
	}

	wrappedKey := data.Get("wrapped_private_key").(string)
	if wrappedKey == "" {
		return nil, errors.New("wrapped_private_key is required")
	}

	privateKeyBytes, err := unwrapPrivateKey(wrappedKey)
	if err != nil {
		return nil, errors.New("failed to unwrap private key: " + err.Error())
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA private key: " + err.Error())
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyString := hexutil.Encode(publicKeyBytes)[4:]

	hash := crypto.Keccak256(publicKeyBytes[1:])
	address := hexutil.Encode(hash[12:])

	return &logical.Response{
		Data: map[string]interface{}{
			"address":    address,
			"public_key": publicKeyString,
		},
	}, nil
}

func unwrapPrivateKey(wrapped string) ([]byte, error) {
	key, err := getOrCreateWrappingKey()
	if err != nil {
		return nil, err
	}
	// Декодируем base64
	ciphertext, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, err
	}
	// Первая часть — зашифрованный AES-ключ (512 байт для RSA-4096)
	if len(ciphertext) < 512 {
		return nil, errors.New("ciphertext too short")
	}
	wrappedAES := ciphertext[:512]
	wrappedTargetKey := ciphertext[512:]

	// Расшифровываем AES-ключ
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrappedAES, []byte{})
	if err != nil {
		return nil, err
	}

	// Распаковываем приватник через KWP (RFC 5649)
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		return nil, err
	}
	privateKey, err := kwp.Unwrap(wrappedTargetKey)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
