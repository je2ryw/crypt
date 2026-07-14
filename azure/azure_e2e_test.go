package azure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/VirtusLab/crypt/crypto"
	"github.com/VirtusLab/crypt/test"
	"github.com/VirtusLab/crypt/test/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptFileWithFake(t *testing.T) {
	keyVault := &KeyVault{
		vaultURL:   "https://key-vault-url.com",
		key:        "key-vault-key",
		keyVersion: "key-vault-key-version",
		client:     fake.KeyVaultAPIClient{},
	}
	crypt := crypto.New(keyVault)
	secret := "uber-secret"
	inputFile := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(inputFile, []byte(secret), 0644))

	actual, err := test.EncryptAndDecryptFile(crypt, crypt, inputFile)

	require.NoError(t, err)
	assert.Equal(t, secret, actual)
}
