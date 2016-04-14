package auth

import (
	"github.com/jhunt/safe/prompt"
)

func Token(addr string) (string, error) {
	return prompt.Secure("Token: "), nil
}
