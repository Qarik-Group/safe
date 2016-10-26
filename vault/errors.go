package vault

import (
	"fmt"
	"regexp"
)

var secretErrorRegexp, keyErrorRegexp *regexp.Regexp

//IsNotFound returns true if the given error is a SecretNotFound error
// 	or a KeyNotFound error. Returns false otherwise.
func IsNotFound(err error) bool {
	return isSecretNotFound(err) || isKeyNotFound(err)
}

//NewSecretNotFoundError returns an error with a message descibing the path
// which could not be found in the secret backend.
func NewSecretNotFoundError(path string) error {
	return fmt.Errorf("no secret exists at path `%s`", path)
}

func isSecretNotFound(err error) bool {
	return secretErrorRegexp.Match([]byte(err.Error()))
}

//NewKeyNotFoundError returns an error object describing the key that could not
// be located within the secret it was searched for in. Returning a KeyNotFound
// error should semantically mean that the secret it would've been contained in
// was located in the vault.
func NewKeyNotFoundError(path, key string) error {
	return fmt.Errorf("no key `%s` exists in secret `%s`", key, path)
}

func isKeyNotFound(err error) bool {
	return keyErrorRegexp.Match([]byte(err.Error()))
}

func init() {
	secretErrorRegexp = regexp.MustCompile("^no secret exists at path `.*`$")
	keyErrorRegexp = regexp.MustCompile("^no key `.*` exists in secret `.*`$")
}
