package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptValidation(t *testing.T) {
	_, err := New("", "us-east-1", DefaultProfile).Encrypt([]byte("plaintext"))
	assert.ErrorIs(t, err, ErrKmsMissing)

	_, err = New("alias/test", "", DefaultProfile).Encrypt([]byte("plaintext"))
	assert.ErrorIs(t, err, ErrRegionMissing)
}

func TestDecryptValidation(t *testing.T) {
	_, err := New("", "", DefaultProfile).Decrypt([]byte("ciphertext"))
	assert.ErrorIs(t, err, ErrRegionMissing)
}
