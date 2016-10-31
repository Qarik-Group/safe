package vault

import (
	"fmt"
	"strings"
	"testing"
)

// ADD TEST CASES HERE
var testSecrets = [...]string{
	"path/to/secret",
	"1234901827",
	"",
	".*",
}

var testKeys = [...]string{
	"key",
	"a/key/this/is",
	"1239487329",
	"",
	":",
	".*",
}

var otherErrorMessages = [...]string{
	"I am not a NotFoundError",
	"looks/like/a/path",
	"looks/like/a/path and looks/like/another/path",
}

var secretErrors, keyErrors, otherErrors []error

func TestNewSecretNotFoundError(t *testing.T) {
	for i, err := range secretErrors {
		//It has the path in it!
		testString := fmt.Sprintf("`%s`", testSecrets[i])
		if !strings.Contains(err.Error(), testString) {
			t.Errorf("Error message `%s` does not contain test string `%s`", err.Error(), testString)
		}
	}
}

func TestNewKeyNotFoundError(t *testing.T) {
	for i, err := range keyErrors {
		//It has the path and the key in it!
		testSecretString := fmt.Sprintf("`%s`", testSecrets[i/len(testKeys)])
		testKeyString := fmt.Sprintf("`%s`", testKeys[i%len(testKeys)])
		for _, str := range []string{testSecretString, testKeyString} {
			if !strings.Contains(err.Error(), str) {
				t.Errorf("Error message `%s` does not contain test string `%s`", err.Error(), str)
			}
		}
	}
}

func TestIsSecretNotFoundPositives(t *testing.T) {
	for _, err := range secretErrors {
		//It is recognized as a SecretNotFoundError
		if !isSecretNotFound(err) {
			t.Errorf("Error with message `%s` not recognized as SecretNotFoundError", err.Error())
		}
	}
}

func TestIsSecretNotFoundNegatives(t *testing.T) {
	//Random other errors aren't SecretNotFoundErrors
	for _, err := range otherErrors {
		if isSecretNotFound(err) {
			t.Errorf("Error with message `%s` was incorrectly recognized as a SecretNotFoundError", err.Error())
		}
	}
	//KeyNotFoundError isn't a SecretNotFoundError
	for _, err := range keyErrors {
		if isSecretNotFound(err) {
			t.Errorf("Error with message `%s` incorrectly recognized as SecretNotFoundError", err.Error())
		}
	}
}

func TestIsKeyNotFoundPositives(t *testing.T) {
	for _, err := range keyErrors {
		//It is recognized as a KeyNotFoundError
		if !isKeyNotFound(err) {
			t.Errorf("Error with message `%s` not recognized as KeyNotFoundError", err.Error())
		}
	}
}

func TestIsKeyNotFoundNegatives(t *testing.T) {
	//Random other errors aren't recognized as KeyNotFoundErrors
	for _, err := range otherErrors {
		if isKeyNotFound(err) {
			t.Errorf("Error with message `%s` was incorrectly recognized as a KeyNotFoundError", err.Error())
		}
	}
	//SecretNotFoundErrors aren't KeyNotFoundErrors
	for _, err := range secretErrors {
		if isKeyNotFound(err) {
			t.Errorf("Error with message `%s` incorrectly recognized as KeyNotFoundError", err.Error())
		}
	}
}

func TestIsNotFoundPositives(t *testing.T) {
	//SecretNotFoundErrors are NotFoundErrors
	for _, err := range secretErrors {
		if !IsNotFound(err) {
			t.Errorf("Error with message `%s` not recognized as NotFoundError", err.Error())
		}
	}
	for _, err := range keyErrors {
		if !IsNotFound(err) {
			t.Errorf("Error with message `%s` not recognized as NotFoundError", err.Error())
		}
	}
}

func TestIsNotFoundNegatives(t *testing.T) {
	for _, err := range otherErrors {
		if IsNotFound(err) {
			t.Errorf("Error with message `%s` incorrectly identified as NotFoundError", err.Error())
		}
	}
}

func init() {

	// Initialize all the error objects
	for _, secret := range testSecrets {
		secretErrors = append(secretErrors, NewSecretNotFoundError(secret))
		for _, key := range testKeys {
			keyErrors = append(keyErrors, NewKeyNotFoundError(secret, key))
		}
	}

	for _, msg := range otherErrorMessages {
		otherErrors = append(otherErrors, fmt.Errorf(msg))
	}
}
