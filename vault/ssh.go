package vault

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
)

func sshkey(bits int) (string, string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", "", err
	}

	private := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pub := key.Public()
	pubkey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", "", err
	}
	public := ssh.MarshalAuthorizedKey(pubkey)

	var fp []string
	f := []byte(fmt.Sprintf("%x", md5.Sum(pubkey.Marshal())))
	for i := 0; i < len(f); i += 2 {
		fp = append(fp, string(f[i:i+2]))
	}
	fingerprint := strings.Join(fp, ":")

	return string(private), string(public), string(fingerprint), nil
}
