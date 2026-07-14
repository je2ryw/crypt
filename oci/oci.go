// Package oci provides encryption and decryption with Oracle Cloud Infrastructure KMS.
package oci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/VirtusLab/crypt/version"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	providerName                        = "oci"
	encryptedFileMetadataSeparator byte = '.'

	// DefaultProfile is the default profile in the OCI configuration file.
	DefaultProfile = "DEFAULT"
	// DefaultAuthType uses an API signing key from an OCI configuration profile.
	DefaultAuthType = "api_key"
	// DefaultAlgorithm is the default OCI KMS encryption algorithm.
	DefaultAlgorithm = "AES_256_GCM"
)

var (
	magicNumber []byte

	// ErrKeyIDMissing is returned when the OCI KMS key OCID is missing.
	ErrKeyIDMissing = errors.New("OCI KMS key ID is empty or missing")
	// ErrCryptoEndpointMissing is returned when the vault crypto endpoint is missing.
	ErrCryptoEndpointMissing = errors.New("OCI KMS crypto endpoint is empty or missing")
	// ErrInvalidAuthType is returned when the configured OCI authentication type is unsupported.
	ErrInvalidAuthType = errors.New("invalid OCI authentication type")
	// ErrInvalidAlgorithm is returned when the configured OCI KMS encryption algorithm is unsupported.
	ErrInvalidAlgorithm = errors.New("invalid OCI KMS encryption algorithm")
)

// Options configures an OCI KMS provider.
type Options struct {
	KeyID          string
	KeyVersionID   string
	CryptoEndpoint string
	Profile        string
	ConfigFile     string
	AuthType       string
	Algorithm      string
}

// MetadataHeader holds the OCI KMS metadata needed to decrypt ciphertext.
type MetadataHeader struct {
	Provider       string `json:"provider"`
	CryptVersion   string `json:"crypt"`
	KeyID          string `json:"keyId"`
	KeyVersionID   string `json:"keyVersionId"`
	CryptoEndpoint string `json:"cryptoEndpoint"`
	Algorithm      string `json:"algorithm"`
}

type cryptoClient interface {
	Encrypt(context.Context, keymanagement.EncryptRequest) (keymanagement.EncryptResponse, error)
	Decrypt(context.Context, keymanagement.DecryptRequest) (keymanagement.DecryptResponse, error)
}

type cryptoClientFactory func(string) (cryptoClient, error)

// KMS encrypts and decrypts data with OCI KMS.
type KMS struct {
	keyID          string
	keyVersionID   string
	cryptoEndpoint string
	profile        string
	configFile     string
	authType       string
	algorithm      string
	client         cryptoClient

	algorithmSet   bool
	clientEndpoint string
	newClient      cryptoClientFactory
}

// New creates an OCI KMS provider using API-key authentication.
func New(keyID, cryptoEndpoint, profile string) *KMS {
	kms, _ := NewWithOptions(Options{
		KeyID:          keyID,
		CryptoEndpoint: cryptoEndpoint,
		Profile:        profile,
	})
	return kms
}

// NewWithOptions creates an OCI KMS provider with the supplied options.
func NewWithOptions(opts Options) (*KMS, error) {
	profile := opts.Profile
	if profile == "" {
		profile = DefaultProfile
	}
	authType := opts.AuthType
	if authType == "" {
		authType = DefaultAuthType
	}
	if !validAuthType(authType) {
		return nil, errors.Wrapf(ErrInvalidAuthType, "error reading auth type: %s", authType)
	}

	algorithm := opts.Algorithm
	algorithmSet := algorithm != ""
	if algorithm == "" {
		algorithm = DefaultAlgorithm
	}
	mappedAlgorithm, ok := keymanagement.GetMappingEncryptDataDetailsEncryptionAlgorithmEnum(algorithm)
	if !ok {
		return nil, errors.Wrapf(ErrInvalidAlgorithm, "error reading algorithm: %s", algorithm)
	}
	algorithm = string(mappedAlgorithm)

	kms := &KMS{
		keyID:          opts.KeyID,
		keyVersionID:   opts.KeyVersionID,
		cryptoEndpoint: opts.CryptoEndpoint,
		profile:        profile,
		configFile:     opts.ConfigFile,
		authType:       authType,
		algorithm:      algorithm,
		algorithmSet:   algorithmSet,
	}
	kms.newClient = kms.createClient
	return kms, nil
}

// Encrypt encrypts plaintext with OCI KMS and returns self-describing ciphertext.
func (k *KMS) Encrypt(plaintext []byte) ([]byte, error) {
	if err := validateKeyAndEndpoint(k.keyID, k.cryptoEndpoint); err != nil {
		return nil, err
	}
	algorithm, err := encryptAlgorithm(k.algorithm)
	if err != nil {
		return nil, err
	}
	if err := k.ensureClient(k.cryptoEndpoint); err != nil {
		return nil, err
	}

	details := keymanagement.EncryptDataDetails{
		KeyId:               common.String(k.keyID),
		Plaintext:           common.String(base64.StdEncoding.EncodeToString(plaintext)),
		EncryptionAlgorithm: algorithm,
	}
	if k.keyVersionID != "" {
		details.KeyVersionId = common.String(k.keyVersionID)
	}
	response, err := k.client.Encrypt(context.Background(), keymanagement.EncryptRequest{EncryptDataDetails: details})
	if err != nil {
		if isOversizedPayloadError(err) {
			return nil, errors.Wrap(err, "OCI KMS rejected the plaintext size; gzip the input or use envelope encryption")
		}
		return nil, errors.WithStack(err)
	}
	if response.Ciphertext == nil {
		return nil, errors.New("OCI KMS encryption response is missing ciphertext")
	}

	metadata := MetadataHeader{
		Provider:       providerName,
		CryptVersion:   version.VERSION,
		KeyID:          stringValue(response.KeyId, k.keyID),
		KeyVersionID:   stringValue(response.KeyVersionId, k.keyVersionID),
		CryptoEndpoint: k.cryptoEndpoint,
		Algorithm:      string(response.EncryptionAlgorithm),
	}
	if metadata.Algorithm == "" {
		metadata.Algorithm = k.algorithm
	}
	result, err := marshalCiphertext(metadata, *response.Ciphertext)
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"keyID":          metadata.KeyID,
		"keyVersionID":   metadata.KeyVersionID,
		"cryptoEndpoint": metadata.CryptoEndpoint,
		"algorithm":      metadata.Algorithm,
	}).Info("Encryption succeeded")
	return result, nil
}

// Decrypt decrypts OCI KMS ciphertext, using metadata from its header when present.
func (k *KMS) Decrypt(ciphertext []byte) ([]byte, error) {
	keyID := k.keyID
	keyVersionID := k.keyVersionID
	cryptoEndpoint := k.cryptoEndpoint
	algorithmName := k.algorithm
	dataToDecrypt := base64.StdEncoding.EncodeToString(ciphertext)

	if bytes.HasPrefix(ciphertext, magicNumber) {
		logrus.Debug("Cipher text contains metadata header")
		metadata, payload, err := unmarshalCiphertext(ciphertext)
		if err != nil {
			return nil, err
		}
		dataToDecrypt = payload
		if keyID == "" {
			keyID = metadata.KeyID
		}
		if keyVersionID == "" {
			keyVersionID = metadata.KeyVersionID
		}
		if cryptoEndpoint == "" {
			cryptoEndpoint = metadata.CryptoEndpoint
		}
		if !k.algorithmSet {
			algorithmName = metadata.Algorithm
		}
	} else {
		logrus.Debug("Cipher text doesn't contain metadata header")
	}

	if err := validateKeyAndEndpoint(keyID, cryptoEndpoint); err != nil {
		return nil, err
	}
	algorithm, err := decryptAlgorithm(algorithmName)
	if err != nil {
		return nil, err
	}
	if err := k.ensureClient(cryptoEndpoint); err != nil {
		return nil, err
	}

	details := keymanagement.DecryptDataDetails{
		KeyId:               common.String(keyID),
		Ciphertext:          common.String(dataToDecrypt),
		EncryptionAlgorithm: algorithm,
	}
	if keyVersionID != "" {
		details.KeyVersionId = common.String(keyVersionID)
	}
	response, err := k.client.Decrypt(context.Background(), keymanagement.DecryptRequest{DecryptDataDetails: details})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if response.Plaintext == nil {
		return nil, errors.New("OCI KMS decryption response is missing plaintext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(*response.Plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding OCI KMS plaintext")
	}

	logrus.WithFields(logrus.Fields{
		"keyID":          keyID,
		"keyVersionID":   keyVersionID,
		"cryptoEndpoint": cryptoEndpoint,
		"algorithm":      algorithmName,
	}).Info("Decryption succeeded")
	return plaintext, nil
}

func (k *KMS) ensureClient(cryptoEndpoint string) error {
	if k.client != nil && (k.newClient == nil || k.clientEndpoint == cryptoEndpoint) {
		return nil
	}
	if k.newClient == nil {
		return errors.New("OCI KMS crypto client is empty")
	}
	client, err := k.newClient(cryptoEndpoint)
	if err != nil {
		return errors.Wrap(err, "failed to create OCI KMS crypto client")
	}
	k.client = client
	k.clientEndpoint = cryptoEndpoint
	return nil
}

func (k *KMS) createClient(cryptoEndpoint string) (cryptoClient, error) {
	provider, err := k.configurationProvider()
	if err != nil {
		return nil, err
	}
	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(provider, cryptoEndpoint)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (k *KMS) configurationProvider() (common.ConfigurationProvider, error) {
	switch k.authType {
	case DefaultAuthType:
		if k.configFile == "" && k.profile == DefaultProfile {
			return common.DefaultConfigProvider(), nil
		}
		return common.CustomProfileConfigProvider(k.configFile, k.profile), nil
	case "instance_principal":
		return auth.InstancePrincipalConfigurationProvider()
	case "resource_principal":
		return auth.ResourcePrincipalConfigurationProvider()
	case "security_token":
		return common.CustomProfileSessionTokenConfigProvider(k.configFile, k.profile), nil
	default:
		return nil, errors.Wrapf(ErrInvalidAuthType, "error reading auth type: %s", k.authType)
	}
}

func marshalCiphertext(metadata MetadataHeader, ciphertext string) ([]byte, error) {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling header metadata")
	}
	metadataEncoded := base64.RawURLEncoding.EncodeToString(metadataBytes)
	result := append([]byte(metadataEncoded), encryptedFileMetadataSeparator)
	return append(result, []byte(ciphertext)...), nil
}

func unmarshalCiphertext(ciphertext []byte) (MetadataHeader, string, error) {
	separator := bytes.IndexByte(ciphertext, encryptedFileMetadataSeparator)
	if separator < 0 {
		return MetadataHeader{}, "", errors.New("OCI ciphertext metadata separator is missing")
	}
	metadataBytes, err := base64.RawURLEncoding.DecodeString(string(ciphertext[:separator]))
	if err != nil {
		return MetadataHeader{}, "", errors.Wrap(err, "error decoding header metadata")
	}
	metadata := MetadataHeader{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return MetadataHeader{}, "", errors.Wrap(err, "error unmarshaling header metadata")
	}
	if metadata.Provider != providerName {
		return MetadataHeader{}, "", errors.Errorf("unexpected ciphertext provider: %s", metadata.Provider)
	}
	return metadata, string(ciphertext[separator+1:]), nil
}

func validateKeyAndEndpoint(keyID, cryptoEndpoint string) error {
	if keyID == "" {
		return errors.Wrapf(ErrKeyIDMissing, "error reading key ID: %s", keyID)
	}
	if cryptoEndpoint == "" {
		return errors.Wrapf(ErrCryptoEndpointMissing, "error reading crypto endpoint: %s", cryptoEndpoint)
	}
	return nil
}

func validAuthType(authType string) bool {
	switch authType {
	case DefaultAuthType, "instance_principal", "resource_principal", "security_token":
		return true
	default:
		return false
	}
}

func encryptAlgorithm(algorithm string) (keymanagement.EncryptDataDetailsEncryptionAlgorithmEnum, error) {
	value, ok := keymanagement.GetMappingEncryptDataDetailsEncryptionAlgorithmEnum(algorithm)
	if !ok {
		return "", errors.Wrapf(ErrInvalidAlgorithm, "error reading algorithm: %s", algorithm)
	}
	return value, nil
}

func decryptAlgorithm(algorithm string) (keymanagement.DecryptDataDetailsEncryptionAlgorithmEnum, error) {
	value, ok := keymanagement.GetMappingDecryptDataDetailsEncryptionAlgorithmEnum(algorithm)
	if !ok {
		return "", errors.Wrapf(ErrInvalidAlgorithm, "error reading algorithm: %s", algorithm)
	}
	return value, nil
}

func stringValue(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}

func isOversizedPayloadError(err error) bool {
	serviceError, ok := common.IsServiceError(err)
	if !ok || (serviceError.GetHTTPStatusCode() != 400 && serviceError.GetHTTPStatusCode() != 413) {
		return false
	}
	message := strings.ToLower(serviceError.GetMessage())
	return strings.Contains(message, "too large") ||
		strings.Contains(message, "maximum size") ||
		(strings.Contains(message, "plaintext") && strings.Contains(message, "limit"))
}

func init() {
	// Keep the source prefix on a complete base64 quantum so its encoding is
	// also a byte prefix of the complete encoded JSON header.
	fileContentPrefix := []byte(`{"provider":"oci","crypt`)
	magicNumber = make([]byte, base64.RawURLEncoding.EncodedLen(len(fileContentPrefix)))
	base64.RawURLEncoding.Encode(magicNumber, fileContentPrefix)
}
