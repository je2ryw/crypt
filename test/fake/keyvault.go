package fake

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// KeyVaultAPIClient is a fake Azure Key Vault client
type KeyVaultAPIClient struct{}

// Encrypt returns the provided plaintext as ciphertext
func (KeyVaultAPIClient) Encrypt(_ context.Context, _, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
	return azkeys.EncryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{Result: parameters.Value},
	}, nil
}

// Decrypt returns the provided ciphertext as plaintext
func (KeyVaultAPIClient) Decrypt(_ context.Context, _, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	return azkeys.DecryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{Result: parameters.Value},
	}, nil
}
