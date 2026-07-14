package oci

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/VirtusLab/crypt/test/fake"
	"github.com/VirtusLab/crypt/version"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKeyID          = "ocid1.key.oc1.ca-toronto-1.test-key"
	testKeyVersionID   = "ocid1.keyversion.oc1.ca-toronto-1.test-version"
	testCryptoEndpoint = "https://test-crypto.kms.ca-toronto-1.oraclecloud.com"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	client := &fake.OCICryptoClient{}
	encrypt := newFakeKMS(t, Options{
		KeyID:          testKeyID,
		KeyVersionID:   testKeyVersionID,
		CryptoEndpoint: testCryptoEndpoint,
	}, client)
	decrypt := newFakeKMS(t, Options{}, client)
	secret := []byte("top secret token")

	ciphertext, err := encrypt.Encrypt(secret)
	require.NoError(t, err)
	plaintext, err := decrypt.Decrypt(ciphertext)

	require.NoError(t, err)
	assert.Equal(t, secret, plaintext)
}

func TestEncryptedDataStructureUsesResponseMetadataAndVerbatimPayload(t *testing.T) {
	responseKeyID := "ocid1.key.response"
	responseKeyVersionID := "ocid1.keyversion.response"
	responseAlgorithm := keymanagement.EncryptedDataEncryptionAlgorithmRsaOaepSha256
	payload := "Q0lQSEVSVEVYVCtQQVlMT0FELw=="
	client := &fake.OCICryptoClient{
		EncryptResponse: &keymanagement.EncryptResponse{
			EncryptedData: keymanagement.EncryptedData{
				Ciphertext:          common.String(payload),
				KeyId:               common.String(responseKeyID),
				KeyVersionId:        common.String(responseKeyVersionID),
				EncryptionAlgorithm: responseAlgorithm,
			},
		},
	}
	kms := newFakeKMS(t, Options{
		KeyID:          testKeyID,
		CryptoEndpoint: testCryptoEndpoint,
	}, client)

	ciphertext, err := kms.Encrypt([]byte("secret"))

	require.NoError(t, err)
	separator := bytes.IndexByte(ciphertext, encryptedFileMetadataSeparator)
	require.NotEqual(t, -1, separator)
	assert.Equal(t, separator, bytes.LastIndexByte(ciphertext, encryptedFileMetadataSeparator))
	assert.Equal(t, payload, string(ciphertext[separator+1:]), "OCI ciphertext payload must pass through verbatim")

	headerJSON, err := base64.RawURLEncoding.DecodeString(string(ciphertext[:separator]))
	require.NoError(t, err)
	expectedHeaderJSON := fmt.Sprintf(
		`{"provider":"oci","crypt":%q,"keyId":"%s","keyVersionId":"%s","cryptoEndpoint":"%s","algorithm":"RSA_OAEP_SHA_256"}`,
		version.VERSION, responseKeyID, responseKeyVersionID, testCryptoEndpoint,
	)
	assert.Equal(t, expectedHeaderJSON, string(headerJSON), "header JSON field names and order are part of the on-disk format")
	var rawHeader map[string]any
	require.NoError(t, json.Unmarshal(headerJSON, &rawHeader))
	assert.Equal(t, map[string]any{
		"provider":       "oci",
		"crypt":          version.VERSION,
		"keyId":          responseKeyID,
		"keyVersionId":   responseKeyVersionID,
		"cryptoEndpoint": testCryptoEndpoint,
		"algorithm":      "RSA_OAEP_SHA_256",
	}, rawHeader)
	assert.True(t, bytes.HasPrefix(ciphertext, magicNumber))
}

func TestDecryptUsesHeaderWithoutKeyFlags(t *testing.T) {
	client := &fake.OCICryptoClient{}
	encrypt := newFakeKMS(t, Options{
		KeyID:          testKeyID,
		KeyVersionID:   testKeyVersionID,
		CryptoEndpoint: testCryptoEndpoint,
		Algorithm:      "RSA_OAEP_SHA_1",
	}, client)
	ciphertext, err := encrypt.Encrypt([]byte("header only"))
	require.NoError(t, err)
	client.DecryptRequests = nil
	decrypt := newFakeKMS(t, Options{}, client)

	plaintext, err := decrypt.Decrypt(ciphertext)

	require.NoError(t, err)
	assert.Equal(t, "header only", string(plaintext))
	require.Len(t, client.DecryptRequests, 1)
	request := client.DecryptRequests[0]
	require.NotNil(t, request.KeyId)
	require.NotNil(t, request.KeyVersionId)
	assert.Equal(t, testKeyID, *request.KeyId)
	assert.Equal(t, testKeyVersionID, *request.KeyVersionId)
	assert.Equal(t, "RSA_OAEP_SHA_1", string(request.EncryptionAlgorithm))
}

func TestDecryptExplicitOptionsOverrideHeader(t *testing.T) {
	header := MetadataHeader{
		Provider:       providerName,
		CryptVersion:   "header-version",
		KeyID:          "header-key",
		KeyVersionID:   "header-key-version",
		CryptoEndpoint: "https://header-endpoint.example.com",
		Algorithm:      "AES_256_GCM",
	}
	ciphertext, err := marshalCiphertext(header, base64.StdEncoding.EncodeToString([]byte("secret")))
	require.NoError(t, err)
	client := &fake.OCICryptoClient{}
	kms, err := NewWithOptions(Options{
		KeyID:          "flag-key",
		KeyVersionID:   "flag-key-version",
		CryptoEndpoint: "https://flag-endpoint.example.com",
		Algorithm:      "RSA_OAEP_SHA_256",
	})
	require.NoError(t, err)
	var clientEndpoint string
	kms.newClient = func(endpoint string) (cryptoClient, error) {
		clientEndpoint = endpoint
		return client, nil
	}

	plaintext, err := kms.Decrypt(ciphertext)

	require.NoError(t, err)
	assert.Equal(t, "secret", string(plaintext))
	assert.Equal(t, "https://flag-endpoint.example.com", clientEndpoint)
	require.Len(t, client.DecryptRequests, 1)
	request := client.DecryptRequests[0]
	require.NotNil(t, request.KeyId)
	require.NotNil(t, request.KeyVersionId)
	assert.Equal(t, "flag-key", *request.KeyId)
	assert.Equal(t, "flag-key-version", *request.KeyVersionId)
	assert.Equal(t, "RSA_OAEP_SHA_256", string(request.EncryptionAlgorithm))
}

func TestDecryptHeaderlessCiphertextUsesFlagsAndBase64EncodesPayload(t *testing.T) {
	rawCiphertext := []byte{0x00, 0x01, 0x02, 0xfa, 0xfb, 0xfc}
	client := &fake.OCICryptoClient{
		DecryptResponse: &keymanagement.DecryptResponse{
			DecryptedData: keymanagement.DecryptedData{
				Plaintext:         common.String(base64.StdEncoding.EncodeToString([]byte("plaintext"))),
				PlaintextChecksum: common.String("checksum"),
			},
		},
	}
	kms := newFakeKMS(t, Options{
		KeyID:          testKeyID,
		CryptoEndpoint: testCryptoEndpoint,
	}, client)

	plaintext, err := kms.Decrypt(rawCiphertext)

	require.NoError(t, err)
	assert.Equal(t, "plaintext", string(plaintext))
	require.Len(t, client.DecryptRequests, 1)
	require.NotNil(t, client.DecryptRequests[0].Ciphertext)
	assert.Equal(t, base64.StdEncoding.EncodeToString(rawCiphertext), *client.DecryptRequests[0].Ciphertext)
}

func TestMissingKeyID(t *testing.T) {
	kms := newFakeKMS(t, Options{CryptoEndpoint: testCryptoEndpoint}, &fake.OCICryptoClient{})

	_, encryptErr := kms.Encrypt([]byte("plaintext"))
	_, decryptErr := kms.Decrypt([]byte("ciphertext"))

	assert.ErrorIs(t, encryptErr, ErrKeyIDMissing)
	assert.ErrorIs(t, decryptErr, ErrKeyIDMissing)
}

func TestMissingCryptoEndpoint(t *testing.T) {
	kms := newFakeKMS(t, Options{KeyID: testKeyID}, &fake.OCICryptoClient{})

	_, encryptErr := kms.Encrypt([]byte("plaintext"))
	_, decryptErr := kms.Decrypt([]byte("ciphertext"))

	assert.ErrorIs(t, encryptErr, ErrCryptoEndpointMissing)
	assert.ErrorIs(t, decryptErr, ErrCryptoEndpointMissing)
}

func TestInvalidAuthType(t *testing.T) {
	_, err := NewWithOptions(Options{AuthType: "password"})

	assert.ErrorIs(t, err, ErrInvalidAuthType)
}

func TestInvalidAlgorithm(t *testing.T) {
	_, err := NewWithOptions(Options{Algorithm: "AES_128_CBC"})

	assert.ErrorIs(t, err, ErrInvalidAlgorithm)
}

func TestSupportedAlgorithmsMatchSDKEnum(t *testing.T) {
	for _, algorithm := range keymanagement.GetEncryptDataDetailsEncryptionAlgorithmEnumStringValues() {
		t.Run(algorithm, func(t *testing.T) {
			kms, err := NewWithOptions(Options{Algorithm: algorithm})

			require.NoError(t, err)
			assert.Equal(t, algorithm, kms.algorithm)
		})
	}
}

func TestOversizedServiceErrorIncludesCompressionHint(t *testing.T) {
	client := &fake.OCICryptoClient{
		EncryptErr: testServiceError{
			status:  400,
			code:    "InvalidParameter",
			message: "plaintext exceeds the maximum size",
		},
	}
	kms := newFakeKMS(t, Options{
		KeyID:          testKeyID,
		CryptoEndpoint: testCryptoEndpoint,
	}, client)

	_, err := kms.Encrypt([]byte("oversized"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gzip the input or use envelope encryption")
	var serviceErr testServiceError
	assert.True(t, errors.As(err, &serviceErr))
}

type testServiceError struct {
	status  int
	code    string
	message string
}

func (e testServiceError) Error() string          { return e.message }
func (e testServiceError) GetHTTPStatusCode() int { return e.status }
func (e testServiceError) GetMessage() string     { return e.message }
func (e testServiceError) GetCode() string        { return e.code }
func (e testServiceError) GetOpcRequestID() string {
	return "test-request"
}

func newFakeKMS(t *testing.T, opts Options, client cryptoClient) *KMS {
	t.Helper()
	kms, err := NewWithOptions(opts)
	require.NoError(t, err)
	kms.client = client
	kms.newClient = nil
	return kms
}
