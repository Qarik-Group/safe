package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/jhunt/go-ansi"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
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

func (s *Secret) Keys() []string {
	keys := reflect.ValueOf(s.data).MapKeys()
	str_keys := make([]string, len(keys))
	for i := 0; i < len(keys); i++ {
		str_keys[i] = keys[i].String()
	}
	sort.Strings(str_keys)
	return str_keys
}

// Set stores a value in the Secret, under the given key.
func (s *Secret) Set(key, value string, skipIfExists bool) error {
	if s.Has(key) && skipIfExists {
		return ansi.Errorf("@R{BUG: Something tried to overwrite the} @C{%s} @R{key, but it already existed, and --no-clobber was specified}", key)
	}
	s.data[key] = value
	return nil
}

// Delete removes the entry with the given key from the Secret.
// Returns true if there was a matching object to delete. False otherwise.
func (s *Secret) Delete(key string) bool {
	if !s.Has(key) {
		return false
	}
	delete(s.data, key)
	return true
}

// Empty returns true if there are no key-value pairs in this Secret object.
// False otherwise.
func (s *Secret) Empty() bool {
	return len(s.data) == 0
}

func (s *Secret) Format(oldKey, newKey, fmtType string, skipIfExists bool) error {
	if !s.Has(oldKey) {
		return NewSecretNotFoundError(oldKey)
	}
	oldVal := s.Get(oldKey)
	switch fmtType {
	case "crypt-md5":
		newVal, err := crypt_md5(oldVal)
		if err != nil {
			return err
		}
		err = s.Set(newKey, newVal, skipIfExists)
		if err != nil {
			return err
		}

	case "crypt-sha256":
		newVal, err := crypt_sha256(oldVal)
		if err != nil {
			return err
		}
		err = s.Set(newKey, newVal, skipIfExists)
		if err != nil {
			return err
		}

	case "crypt-sha512":
		newVal, err := crypt_sha512(oldVal)
		if err != nil {
			return err
		}
		err = s.Set(newKey, newVal, skipIfExists)
		if err != nil {
			return err
		}

	case "bcrypt":
		newVal, err := crypt_bcrypt(oldVal)
		if err != nil {
			return err
		}
		err = s.Set(newKey, newVal, skipIfExists)
		if err != nil {
			return err
		}

	case "base64":
		err := s.Set(newKey, base64.StdEncoding.EncodeToString([]byte(oldVal)), skipIfExists)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s is not a valid encoding for the `safe fmt` command", fmtType)
	}

	return nil
}

func (s *Secret) DHParam(length int, skipIfExists bool) error {
	dhparam, err := genDHParam(length)
	if err != nil {
		return err
	}
	err = s.Set("dhparam-pem", dhparam, skipIfExists)
	if err != nil {
		return err
	}
	return nil
}

// Password creates and stores a new randomized password.
func (s *Secret) Password(key string, length int, policy string, skipIfExists bool) error {
	r, err := random(length, policy)
	if err != nil {
		return err
	}
	err = s.Set(key, r, skipIfExists)
	if err != nil {
		return err
	}
	return nil
}

func crypt_md5(pass string) (string, error) {
	c := md5_crypt.New()
	salt, err := random(16, "a-zA-Z")
	if err != nil {
		return "", err
	}
	md5, err := c.Generate([]byte(pass), []byte("$1$"+salt))
	if err != nil {
		return "", fmt.Errorf("Error generating MD5 crypt for password: %s\n", err)
	}
	return md5, err
}

func crypt_sha256(pass string) (string, error) {
	c := sha256_crypt.New()
	salt, err := random(16, "a-zA-Z")
	if err != nil {
		return "", err
	}
	sha, err := c.Generate([]byte(pass), []byte("$5$"+salt))
	if err != nil {
		return "", fmt.Errorf("Error generating SHA-256 crypt for password: %s\n", err)
	}
	return sha, err
}

func crypt_sha512(pass string) (string, error) {
	c := sha512_crypt.New()
	salt, err := random(16, "a-zA-Z")
	if err != nil {
		return "", err
	}
	sha, err := c.Generate([]byte(pass), []byte("$6$"+salt))
	if err != nil {
		return "", fmt.Errorf("Error generating SHA-512 crypt for password: %s\n", err)
	}
	return sha, err
}

func crypt_bcrypt(pass string) (string, error) {
	// for now, use a fixed worker cost of 12
	hashed, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func (s *Secret) keypair(private, public string, fingerprint string, skipIfExists bool) error {
	err := s.Set("private", private, skipIfExists)
	if err != nil {
		return err
	}
	err = s.Set("public", public, skipIfExists)
	if err != nil {
		return err
	}
	if fingerprint != "" {
		err = s.Set("fingerprint", fingerprint, skipIfExists)
		if err != nil {
			return err
		}
	}
	return nil
}

// RSAKey generates a new public/private keypair, and stores
// it in the secret, under the 'public' and 'private' keys.
func (s *Secret) RSAKey(bits int, skipIfExists bool) error {
	private, public, err := rsakey(bits)
	if err != nil {
		return err
	}
	return s.keypair(private, public, "", skipIfExists)
}

// SSHKey generates a new public/private keypair, and stores
// it in the secret, under the 'public' and 'private' keys.
func (s *Secret) SSHKey(bits int, skipIfExists bool) error {
	private, public, fingerprint, err := sshkey(bits)
	if err != nil {
		return err
	}
	return s.keypair(private, public, fingerprint, skipIfExists)
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

// SingleValue converts a secret to a string representing the value extracted.
// Returns an error if there are not exactly one results in the secret
// object
func (s *Secret) SingleValue() (string, error) {
	if len(s.data) != 1 {
		return "", fmt.Errorf("%d results in secret, 1 expected", len(s.data))
	}
	var ret string
	for _, v := range s.data {
		ret = v
	}
	return ret, nil
}
