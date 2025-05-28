// Copyright © 2020 Kaleido
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/sha3"
)

const (
	// InvalidAddress intends to prevent empty address_to
	InvalidAddress string = "InvalidAddress"
)

var (
	wrappingKey     *rsa.PrivateKey
	wrappingKeyOnce sync.Once
)

// Account is an Ethereum account
type Account struct {
	Address           string    `json:"address"`
	PrivateKey        string    `json:"private_key"`
	PublicKey         string    `json:"public_key"`
	SecretID          uuid.UUID `json:"secret_id"`
	WrappedPrivateKey string    `json:"wrapped_private_key"`
}

func paths(b *backend) []*framework.Path {
	return []*framework.Path{
		pathCreateAndRead(b),
		pathSign(b),
		pathExport(b),
		pathEthereumImport(b),
		pathEthereumWrappingKey(b),
		//pathReadAndDelete(b),
		//pathPublic(b),
	}
}

func (b *backend) listAccounts(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		b.Logger().Error("Failed to retrieve the list of accounts", "error", err)
		return nil, err
	}

	return logical.ListResponse(vals), nil
}

func (b *backend) createAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretIDStr := data.Get("secret_id").(string)
	if secretIDStr == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	secretID, err := uuid.Parse(secretIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid secret_id format: %v", err)
	}

	existingAccount, err := b.retrieveAccountBySecretID(ctx, req, secretID.String())
	if err != nil {
		return nil, err
	}
	if existingAccount != nil {
		return &logical.Response{
			Data: map[string]interface{}{
				"address":    existingAccount.Address,
				"public_key": existingAccount.PublicKey,
				"secret_id":  existingAccount.SecretID,
			},
		}, nil
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	defer ZeroKey(privateKey)

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyString := hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyString := hexutil.Encode(publicKeyBytes)[4:]

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	address := hexutil.Encode(hash.Sum(nil)[12:])

	accountPath := fmt.Sprintf("accounts/%s", secretID.String())

	accountJSON := &Account{
		Address:    address,
		PrivateKey: privateKeyString,
		PublicKey:  publicKeyString,
		SecretID:   secretID,
	}

	entry, _ := logical.StorageEntryJSON(accountPath, accountJSON)
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		b.Logger().Error("Failed to save the new account to storage", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":    accountJSON.Address,
			"public_key": accountJSON.PublicKey,
			"secret_id":  accountJSON.SecretID,
		},
	}, nil
}

func (b *backend) retrieveAccountBySecretID(ctx context.Context, req *logical.Request, secretID string) (*Account, error) {
	path := fmt.Sprintf("accounts/%s", secretID)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		b.Logger().Error("Failed to retrieve the account by secret ID", "path", path, "error", err)
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var account Account
	if err := entry.DecodeJSON(&account); err != nil {
		return nil, err
	}
	return &account, nil
}

func (b *backend) readAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	address := data.Get("name").(string)
	b.Logger().Info("Retrieving account for address", "address", address)
	account, err := b.retrieveAccount(ctx, req, address)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("Account does not exist")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.Address,
		},
	}, nil
}

func (b *backend) exportAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID := data.Get("secret_id").(string)
	b.Logger().Info("Retrieving account for secret_id", "secret_id", secretID)
	account, err := b.retrieveAccountBySecretID(ctx, req, secretID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("Account does not exist")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":    account.Address,
			"privateKey": account.PrivateKey,
			"secret_id":  account.SecretID,
		},
	}, nil
}

func (b *backend) deleteAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	address := data.Get("name").(string)
	account, err := b.retrieveAccount(ctx, req, address)
	if err != nil {
		b.Logger().Error("Failed to retrieve the account by address", "address", address, "error", err)
		return nil, err
	}
	if account == nil {
		return nil, nil
	}
	if err := req.Storage.Delete(ctx, fmt.Sprintf("accounts/%s", account.Address)); err != nil {
		b.Logger().Error("Failed to delete the account from storage", "address", address, "error", err)
		return nil, err
	}
	return nil, nil
}

func (b *backend) retrieveAccount(ctx context.Context, req *logical.Request, address string) (*Account, error) {
	var path string
	matched, err := regexp.MatchString("^(0x)?[0-9a-fA-F]{40}$", address)
	if !matched || err != nil {
		b.Logger().Error("Failed to retrieve the account, malformatted account address", "address", address, "error", err)
		return nil, fmt.Errorf("Failed to retrieve the account, malformatted account address")
	} else {
		// make sure the address has the "0x prefix"
		if address[:2] != "0x" {
			address = "0x" + address
		}
		path = fmt.Sprintf("accounts/%s", address)
		entry, err := req.Storage.Get(ctx, path)
		if err != nil {
			b.Logger().Error("Failed to retrieve the account by address", "path", path, "error", err)
			return nil, err
		}
		if entry == nil {
			// could not find the corresponding key for the address
			return nil, nil
		}
		var account Account
		_ = entry.DecodeJSON(&account)
		return &account, nil
	}
}

func (b *backend) signTx(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID := data.Get("secret_id").(string)
	if secretID == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	account, err := b.retrieveAccountBySecretID(ctx, req, secretID)
	if err != nil {
		b.Logger().Error("Failed to retrieve the signing account", "secret_id", secretID, "error", err)
		return nil, fmt.Errorf("Error retrieving signing account with secret_id %s", secretID)
	}
	if account == nil {
		return nil, fmt.Errorf("Signing account with secret_id %s does not exist", secretID)
	}

	var txDataToSign []byte
	dataInput := data.Get("data").(string)
	// some client such as go-ethereum uses "input" instead of "data"
	if dataInput == "" {
		dataInput = data.Get("input").(string)
	}
	if len(dataInput) > 2 && dataInput[0:2] != "0x" {
		dataInput = "0x" + dataInput
	}

	txDataToSign, err = hexutil.Decode(dataInput)
	if err != nil {
		b.Logger().Error("Failed to decode payload for the 'data' field", "error", err)
		return nil, err
	}

	amount := ValidNumber(data.Get("value").(string))
	if amount == nil {
		b.Logger().Error("Invalid amount for the 'value' field", "value", data.Get("value").(string))
		return nil, fmt.Errorf("Invalid amount for the 'value' field")
	}

	rawAddressTo := data.Get("to").(string)

	chainId := ValidNumber(data.Get("chainId").(string))
	if chainId == nil {
		b.Logger().Error("Invalid chainId", "chainId", data.Get("chainId").(string))
		return nil, fmt.Errorf("Invalid 'chainId' value")
	}

	gasLimitIn := ValidNumber(data.Get("gas").(string))
	if gasLimitIn == nil {
		b.Logger().Error("Invalid gas limit", "gas", data.Get("gas").(string))
		return nil, fmt.Errorf("Invalid gas limit")
	}
	gasLimit := gasLimitIn.Uint64()

	gasPrice := ValidNumber(data.Get("gasPrice").(string))

	nonceIn := ValidNumber(data.Get("nonce").(string))
	var nonce uint64
	nonce = nonceIn.Uint64()

	var tx *types.Transaction
	if rawAddressTo == "" {
		tx = types.NewContractCreation(nonce, amount, gasLimit, gasPrice, txDataToSign)
	} else {
		toAddress := common.HexToAddress(rawAddressTo)
		tx = types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, txDataToSign)
	}
	var signer types.Signer
	if big.NewInt(0).Cmp(chainId) == 0 {
		signer = types.HomesteadSigner{}
	} else {
		signer = types.NewEIP155Signer(chainId)
	}

	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		defer ZeroKey(privateKey)
		b.Logger().Error("Error reconstructing private key from retrieved hex", "error", err)
		return nil, fmt.Errorf("Error reconstructing private key from retrieved hex")
	}

	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		defer ZeroKey(privateKey)
		b.Logger().Error("Failed to sign the transaction object", "error", err)
		return nil, err
	}
	defer ZeroKey(privateKey)

	var signedTxBuff bytes.Buffer
	signedTx.EncodeRLP(&signedTxBuff)

	return &logical.Response{
		Data: map[string]interface{}{
			"transaction_hash":   signedTx.Hash().Hex(),
			"signed_transaction": hexutil.Encode(signedTxBuff.Bytes()),
		},
	}, nil
}

func ValidNumber(input string) *big.Int {
	if input == "" {
		return big.NewInt(0)
	}
	matched, err := regexp.MatchString("([0-9])", input)
	if !matched || err != nil {
		return nil
	}
	amount := math.MustParseBig256(input)
	return amount.Abs(amount)
}

func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
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
