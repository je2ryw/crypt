package fake

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// OCICryptoClient is a configurable fake OCI KMS crypto client.
type OCICryptoClient struct {
	EncryptRequests []keymanagement.EncryptRequest
	DecryptRequests []keymanagement.DecryptRequest
	EncryptResponse *keymanagement.EncryptResponse
	DecryptResponse *keymanagement.DecryptResponse
	EncryptErr      error
	DecryptErr      error
}

// Encrypt records the request and returns either the configured response or a passthrough response.
func (c *OCICryptoClient) Encrypt(_ context.Context, request keymanagement.EncryptRequest) (keymanagement.EncryptResponse, error) {
	c.EncryptRequests = append(c.EncryptRequests, request)
	if c.EncryptErr != nil {
		return keymanagement.EncryptResponse{}, c.EncryptErr
	}
	if c.EncryptResponse != nil {
		return *c.EncryptResponse, nil
	}
	return keymanagement.EncryptResponse{
		EncryptedData: keymanagement.EncryptedData{
			Ciphertext:          request.Plaintext,
			KeyId:               request.KeyId,
			KeyVersionId:        request.KeyVersionId,
			EncryptionAlgorithm: keymanagement.EncryptedDataEncryptionAlgorithmEnum(request.EncryptionAlgorithm),
		},
	}, nil
}

// Decrypt records the request and returns either the configured response or a passthrough response.
func (c *OCICryptoClient) Decrypt(_ context.Context, request keymanagement.DecryptRequest) (keymanagement.DecryptResponse, error) {
	c.DecryptRequests = append(c.DecryptRequests, request)
	if c.DecryptErr != nil {
		return keymanagement.DecryptResponse{}, c.DecryptErr
	}
	if c.DecryptResponse != nil {
		return *c.DecryptResponse, nil
	}
	return keymanagement.DecryptResponse{
		DecryptedData: keymanagement.DecryptedData{
			Plaintext:           request.Ciphertext,
			PlaintextChecksum:   common.String("fake-checksum"),
			KeyId:               request.KeyId,
			KeyVersionId:        request.KeyVersionId,
			EncryptionAlgorithm: keymanagement.DecryptedDataEncryptionAlgorithmEnum(request.EncryptionAlgorithm),
		},
	}, nil
}
