package azure

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/VirtusLab/crypt/test/fake"
	"github.com/VirtusLab/crypt/version"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptedDataStructure(t *testing.T) {
	crypto := KeyVault{
		vaultURL:   "https://key-vault-url.com",
		key:        "key-vault-key",
		keyVersion: "das87d8asgd",
		client:     fake.KeyVaultAPIClient{},
	}
	secret := "top secret token"

	encrypted, err := crypto.Encrypt([]byte(secret))

	require.NoError(t, err)
	indexOfSeparator := bytes.IndexByte(encrypted, encryptedFileMetadataSeparator)
	lastIndex := bytes.LastIndexByte(encrypted, encryptedFileMetadataSeparator)
	assert.NotEqual(t, -1, indexOfSeparator, "encrypted data should contain '.' separator")
	assert.Equal(t, indexOfSeparator, lastIndex, "encrypted data should contain only one '.' separator")

	metadata := MetadataHeader{}
	metadataURLDecoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encrypted[:indexOfSeparator])))
	_, err = base64.RawURLEncoding.Decode(metadataURLDecoded, encrypted[:indexOfSeparator])
	require.NoError(t, err, "metadata header should be encoded with base64")
	err = json.Unmarshal(metadataURLDecoded, &metadata)
	require.NoError(t, err, "metadata header can't be parsed")
	assert.Equal(t, crypto.keyVersion, metadata.AzureKeyVaultKeyVersion)
	assert.Equal(t, crypto.key, metadata.AzureKeyVaultKeyName)
	assert.Equal(t, crypto.vaultURL, metadata.AzureKeyVaultURL)
	assert.Equal(t, version.VERSION, metadata.CryptVersion)

	dataToDecrypt := string(encrypted[indexOfSeparator+1:])
	decrypted, err := base64.RawURLEncoding.DecodeString(string(dataToDecrypt))
	require.NoError(t, err, "encrypted data should be encoded with base64")
	assert.Equal(t, secret, string(decrypted))
}

func TestDecryptPreMigrationCiphertext(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/pre-migration-ciphertext.crypt")
	require.NoError(t, err)
	crypto := KeyVault{client: fake.KeyVaultAPIClient{}}

	decrypted, err := crypto.Decrypt(ciphertext)

	require.NoError(t, err)
	assert.Equal(t, "top secret token", string(decrypted))
	assert.Equal(t, "https://key-vault-url.com", crypto.vaultURL)
	assert.Equal(t, "key-vault-key", crypto.key)
	assert.Equal(t, "das87d8asgd", crypto.keyVersion)
}

func TestEmptyKeyVersionUsesLatest(t *testing.T) {
	crypto := KeyVault{
		vaultURL: "https://key-vault-url.com",
		key:      "key-vault-key",
		client:   fake.KeyVaultAPIClient{},
	}

	encrypted, err := crypto.Encrypt([]byte("top secret token"))
	require.NoError(t, err)
	decrypted, err := crypto.Decrypt(encrypted)

	require.NoError(t, err)
	assert.Equal(t, "top secret token", string(decrypted))
}
