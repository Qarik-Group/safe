package vault

import (
	"encoding/pem"
	"crypto/rsa"
	"crypto/x509"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
)

func sshkey(bits int) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	private := pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pub := key.Public()
	pubkey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	public := ssh.MarshalAuthorizedKey(pubkey)

	return string(private), string(public), nil
}
