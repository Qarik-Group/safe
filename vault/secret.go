package vault

import (
	"encoding/json"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/kless/osutil/user/crypt/sha512_crypt"
	"os"
)

// A Secret contains a set of key/value pairs that store anything you
// want, including passwords, RSAKey keys, usernames, etc.
type Secret struct {
	data map[string]string
}

func NewSecret() *Secret {
	return &Secret{make(map[string]string)}
}

func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.data)
}

func (s *Secret) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.data)
}

// Has returns true if the Secret has defined the given key.
func (s *Secret) Has(key string) bool {
	_, ok := s.data[key]
	return ok
}

// Get retrieves the value of the given key, or "" if no such key exists.
func (s *Secret) Get(key string) string {
	x, _ := s.data[key]
	return x
}

// Set stores a value in the Secret, under the given key.
func (s *Secret) Set(key, value string) {
	s.data[key] = value
}

// Password creates and stores a new randomized password.
func (s *Secret) Password(key string, length int) {
	s.data[key] = random(length)
	s.data[key+"-crypt"] = crypt(s.data[key])
}

func crypt(pass string) string {
	c := sha512_crypt.New()
	sha, err := c.Generate([]byte(pass), []byte("$6$"+random(16)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating crypt for password: %s\n", err)
		return ""
	}
	return sha
}

func (s *Secret) keypair(private, public string, fingerprint string, err error) error {
	if err != nil {
		return err
	}
	s.data["private"] = private
	s.data["public"] = public
	if fingerprint != "" {
		s.data["fingerprint"] = fingerprint
	}
	return nil
}

// RSAKey generates a new public/private keypair, and stores
// it in the secret, under the 'public' and 'private' keys.
func (s *Secret) RSAKey(bits int) error {
	return s.keypair(rsakey(bits))
}

// SSHKey generates a new public/private keypair, and stores
// it in the secret, under the 'public' and 'private' keys.
func (s *Secret) SSHKey(bits int) error {
	return s.keypair(sshkey(bits))
}

// JSON converts a Secret to its JSON representation and returns it as a string.
// Returns an empty string if there were any errors.
func (s *Secret) JSON() string {
	b, err := json.Marshal(s.data)
	if err != nil {
		return ""
	}
	return string(b)
}

// YAML converts a Secret to its YAML representation and returns it as a string.
// Returns an empty string if there were any errors.
func (s *Secret) YAML() string {
	b, err := yaml.Marshal(s.data)
	if err != nil {
		return ""
	}
	return string(b)
}
