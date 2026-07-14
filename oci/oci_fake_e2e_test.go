package oci

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
	client := &fake.OCICryptoClient{}
	encrypt := newFakeKMS(t, Options{
		KeyID:          testKeyID,
		KeyVersionID:   testKeyVersionID,
		CryptoEndpoint: testCryptoEndpoint,
	}, client)
	decrypt := newFakeKMS(t, Options{}, client)
	secret := "uber-secret"
	inputFile := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(inputFile, []byte(secret), 0644))

	actual, err := test.EncryptAndDecryptFile(crypto.New(encrypt), crypto.New(decrypt), inputFile)

	require.NoError(t, err)
	assert.Equal(t, secret, actual)
}
