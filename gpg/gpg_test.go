package gpg

import (
	"os"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptWithKeys(t *testing.T) {
	config := &packet.Config{KeyLifetimeSecs: 0}
	entity, err := openpgp.NewEntity("crypt test", "", "crypt@example.com", config)
	require.NoError(t, err)

	publicKey, err := os.CreateTemp(t.TempDir(), "public-*.gpg")
	require.NoError(t, err)
	publicKeyWriter, err := armor.Encode(publicKey, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, entity.Serialize(publicKeyWriter))
	require.NoError(t, publicKeyWriter.Close())
	require.NoError(t, publicKey.Close())

	privateKey, err := os.CreateTemp(t.TempDir(), "private-*.gpg")
	require.NoError(t, err)
	privateKeyWriter, err := armor.Encode(privateKey, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, entity.SerializePrivate(privateKeyWriter, config))
	require.NoError(t, privateKeyWriter.Close())
	require.NoError(t, privateKey.Close())

	gnupg, err := New(publicKey.Name(), privateKey.Name(), "", "", "")
	require.NoError(t, err)

	plaintext := "TOP SECRET"
	ciphertext, err := gnupg.Encrypt([]byte(plaintext))
	require.NoError(t, err)

	decrypted, err := gnupg.Decrypt(ciphertext)
	require.NoError(t, err)

	require.Equal(t, string(decrypted), plaintext)
}

func TestEncryptWithKeyServer(t *testing.T) {
	keyServer := "keyserver.ubuntu.com"
	keyID := "51716619E084DAB9"
	gnupg, err := New("", "", "", keyID, keyServer)
	require.NoError(t, err)

	plaintext := "TOP SECRET"
	_, err = gnupg.Encrypt([]byte(plaintext))
	require.NoError(t, err)
}
