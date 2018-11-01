package proxy

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type HostKey struct {
	publicKeyChannel chan ssh.PublicKey
	dialErrorChannel chan error
}

func NewHostKey() HostKey {
	return HostKey{
		publicKeyChannel: make(chan ssh.PublicKey),
		dialErrorChannel: make(chan error),
	}
}

func (h HostKey) Get(username, privateKey, serverURL string) (ssh.PublicKey, error) {
	if username == "" {
		username = "jumpbox"
	}

	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	clientConfig := NewSSHClientConfig(username, h.keyScanCallback, ssh.PublicKeys(signer))

	go func() {
		conn, err := ssh.Dial("tcp", serverURL, clientConfig)
		if err != nil {
			h.publicKeyChannel <- nil
			h.dialErrorChannel <- err
			return
		}
		defer conn.Close()
		h.dialErrorChannel <- nil
	}()

	return <-h.publicKeyChannel, <-h.dialErrorChannel
}

func (h HostKey) keyScanCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	h.publicKeyChannel <- key
	return nil
}
