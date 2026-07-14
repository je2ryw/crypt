package azure

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/VirtusLab/crypt/version"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	providerName                        = "az"
	encryptedFileMetadataSeparator byte = '.'
)

var (
	magicNumber []byte
	// ErrVaultURLMissing - this is the custom error, returned when vault url is missing
	ErrVaultURLMissing = errors.New("key vault URL is empty or missing")
	// ErrKeyMissing = this is the custom error, returned when the KeyVault key is missing
	ErrKeyMissing = errors.New("key vault key is empty or missing")
	// ErrKeyVersionMissing = this is the custom error, returned when the KeyVault key version is missing
	ErrKeyVersionMissing = errors.New("key vault key version is empty or missing")
)

// MetadataHeader holds information about KeyVault key used to encrypt
type MetadataHeader struct {
	Provider                string `json:"provider"`
	CryptVersion            string `json:"crypt"`
	AzureKeyVaultURL        string `json:"kvURL"`
	AzureKeyVaultKeyName    string `json:"kvKey"`
	AzureKeyVaultKeyVersion string `json:"kvKeyVer"`
}

type cryptoClient interface {
	Encrypt(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.EncryptOptions) (azkeys.EncryptResponse, error)
	Decrypt(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
}

type cryptoClientFactory func(string) (cryptoClient, error)

// KeyVault struct represents Azure Key Vault
type KeyVault struct {
	vaultURL       string
	key            string
	keyVersion     string
	client         cryptoClient
	clientVaultURL string
	newClient      cryptoClientFactory
}

// New creates Azure Key Vault KeyVault
func New(vaultURL, key, keyVersion string) (*KeyVault, error) {
	credential, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Azure Authorizer")
	}
	newClient := func(vaultURL string) (cryptoClient, error) {
		return azkeys.NewClient(vaultURL, credential, nil)
	}
	return &KeyVault{
		vaultURL:   vaultURL,
		key:        key,
		keyVersion: keyVersion,
		newClient:  newClient,
	}, nil
}

func (k *KeyVault) ensureClient() error {
	if k.client != nil && (k.newClient == nil || k.clientVaultURL == k.vaultURL) {
		return nil
	}
	if k.newClient == nil {
		return errors.New("Azure Key Vault client is empty")
	}
	vaultClient, err := k.newClient(k.vaultURL)
	if err != nil {
		return errors.Wrap(err, "failed to create Azure Key Vault client")
	}
	k.client = vaultClient
	k.clientVaultURL = k.vaultURL
	return nil
}

// Encrypt encrypts plaintext using Azure Key Vault and returns ciphertext
// See Crypt.Encrypt
func (k *KeyVault) Encrypt(plaintext []byte) ([]byte, error) {
	return k.encrypt(plaintext, true)
}

func (k *KeyVault) encrypt(plaintext []byte, includeHeader bool) ([]byte, error) {
	err := k.validate()
	if err != nil {
		return nil, err // err already wrapped in validate function
	}

	if err := k.ensureClient(); err != nil {
		return nil, err
	}

	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256
	p := azkeys.KeyOperationParameters{Value: plaintext, Algorithm: &algorithm}

	res, err := k.client.Encrypt(context.Background(), k.key, k.keyVersion, p, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if includeHeader {
		metadata := MetadataHeader{
			Provider:                providerName,
			CryptVersion:            version.VERSION,
			AzureKeyVaultURL:        k.vaultURL,
			AzureKeyVaultKeyName:    k.key,
			AzureKeyVaultKeyVersion: k.keyVersion,
		}

		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return nil, errors.Wrap(err, "error with marshaling header metadata")
		}
		metadataURLEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(metadataBytes)))
		base64.RawURLEncoding.Encode(metadataURLEncoded, metadataBytes)

		logrus.WithFields(logrus.Fields{
			"keyVaultURL": k.vaultURL,
			"key":         k.key,
			"keyVersion":  k.keyVersion,
		}).Info("Encryption succeeded")
		result := append(metadataURLEncoded, encryptedFileMetadataSeparator)
		result = append(result, []byte(base64.RawURLEncoding.EncodeToString(res.Result))...)
		return result, nil
	}
	logrus.WithFields(logrus.Fields{
		"key":        k.key,
		"keyVersion": k.keyVersion,
	}).Info("Encryption succeeded")
	return res.Result, nil
}

// Decrypt is responsible for decrypting ciphertext by Azure Key Vault encryption key and returning plaintext in bytes.
// See Crypt.EncryptFile
func (k *KeyVault) Decrypt(ciphertext []byte) ([]byte, error) {
	var dataToDecrypt []byte
	if !bytes.HasPrefix(ciphertext, magicNumber) {
		logrus.Debug("Cipher text doesn't contains metadata header")
		dataToDecrypt = ciphertext
	} else {
		logrus.Debug("Cipher text contains metadata header")
		indexOfSeparator := bytes.IndexByte(ciphertext, encryptedFileMetadataSeparator)
		var err error
		dataToDecrypt, err = base64.RawURLEncoding.DecodeString(string(ciphertext[indexOfSeparator+1:]))
		if err != nil {
			return nil, errors.Wrap(err, "error with decoding data")
		}
		metadata := MetadataHeader{}
		metadataURLDecoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(ciphertext[:indexOfSeparator])))
		_, err = base64.RawURLEncoding.Decode(metadataURLDecoded, ciphertext[:indexOfSeparator])
		if err != nil {
			return nil, errors.Wrap(err, "error with decoding header metadata")
		}
		err = json.Unmarshal(metadataURLDecoded, &metadata)
		if err != nil {
			return nil, errors.Wrap(err, "error with unmarshaling header metadata")
		}
		k.vaultURL = metadata.AzureKeyVaultURL
		k.key = metadata.AzureKeyVaultKeyName
		k.keyVersion = metadata.AzureKeyVaultKeyVersion
	}

	if err := k.validate(); err != nil {
		return nil, err // err already wrapped in validate function
	}
	if err := k.ensureClient(); err != nil {
		return nil, err
	}

	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256
	p := azkeys.KeyOperationParameters{Value: dataToDecrypt, Algorithm: &algorithm}

	res, err := k.client.Decrypt(context.Background(), k.key, k.keyVersion, p, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	logrus.WithFields(logrus.Fields{
		"keyVaultURL": k.vaultURL,
		"key":         k.key,
		"keyVersion":  k.keyVersion,
	}).Info("Decryption succeeded")

	return res.Result, nil
}

func (k *KeyVault) validate() error {
	if len(k.vaultURL) == 0 {
		return errors.Wrapf(ErrVaultURLMissing, "error reading vaultURL: %v", k.vaultURL)
	}
	if len(k.key) == 0 {
		return errors.Wrapf(ErrKeyMissing, "error reading key: %v", k.key)
	}
	return nil
}

func init() {
	fileContentPrefix := []byte(`{"provider":"az","crypt"`)
	magicNumber = make([]byte, base64.RawURLEncoding.EncodedLen(len(fileContentPrefix)))
	base64.RawURLEncoding.Encode(magicNumber, fileContentPrefix)
}
