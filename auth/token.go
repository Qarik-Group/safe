package auth

import (
	"github.com/starkandwayne/safe/prompt"
)

func Token(addr string) (string, error) {
	return prompt.Secure("Token: "), nil
}
