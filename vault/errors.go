package vault

import "fmt"

type secretNotFound struct {
	secret string
}

func (e secretNotFound) Error() string {
	return fmt.Sprintf("no secret exists at path `%s`", e.secret)
}

type keyNotFound struct {
	secret string
	key    string
}

func (e keyNotFound) Error() string {
	return fmt.Sprintf("no key `%s` exists in secret `%s`", e.key, e.secret)
}

//IsNotFound returns true if the given error is a SecretNotFound error
// 	or a KeyNotFound error. Returns false otherwise.
func IsNotFound(err error) bool {
	return IsSecretNotFound(err) || IsKeyNotFound(err)
}

//NewSecretNotFoundError returns an error with a message descibing the path
// which could not be found in the secret backend.
func NewSecretNotFoundError(path string) error {
	return secretNotFound{path}
}

//IsSecretNotFound returns true if the given error was created with
// NewSecretNotFoundError().  False otherwise.
func IsSecretNotFound(err error) bool {
	_, is := err.(secretNotFound)
	return is
}

//NewKeyNotFoundError returns an error object describing the key that could not
// be located within the secret it was searched for in. Returning a KeyNotFound
// error should semantically mean that the secret it would've been contained in
// was located in the vault.
func NewKeyNotFoundError(path, key string) error {
	return keyNotFound{secret: path, key: key}
}

//IsKeyNotFound returns true if the given error was created with
// NewKeyNotFoundError(). False otherwise.
func IsKeyNotFound(err error) bool {
	_, is := err.(keyNotFound)
	return is
}
