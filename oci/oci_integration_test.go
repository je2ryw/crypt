//go:build integration
// +build integration

package oci

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/VirtusLab/crypt/crypto"
	"github.com/VirtusLab/crypt/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptWithOCI(t *testing.T) {
	keyID := os.Getenv("OCI_KMS_KEY_ID")
	cryptoEndpoint := os.Getenv("OCI_KMS_CRYPTO_ENDPOINT")
	if keyID == "" || cryptoEndpoint == "" {
		t.Skip("OCI_KMS_KEY_ID and OCI_KMS_CRYPTO_ENDPOINT are required for OCI integration tests")
	}

	encrypt := crypto.New(New(keyID, cryptoEndpoint, os.Getenv("OCI_CLI_PROFILE")))
	decrypt := crypto.New(New("", "", os.Getenv("OCI_CLI_PROFILE")))
	inputFile := filepath.Join(t.TempDir(), "secret.txt")
	expected := "top secret token"
	require.NoError(t, os.WriteFile(inputFile, []byte(expected), 0644))

	actual, err := test.EncryptAndDecryptFile(encrypt, decrypt, inputFile)

	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}
