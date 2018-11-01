package proxy

import (
	"golang.org/x/crypto/ssh"
	"time"
)

func NewSSHClientConfig(user string, hostKeyCallback ssh.HostKeyCallback, authMethods ...ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		Timeout:         30 * time.Second,
		User:            user,
		HostKeyCallback: hostKeyCallback,
		Auth:            authMethods,
	}
}
