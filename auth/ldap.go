package auth

import (
	"strings"
	"net/http"
	"encoding/json"

	"github.com/jhunt/safe/prompt"
)

func LDAP(addr string) (string, error) {
	username := prompt.Normal("LDAP username: ")
	password := prompt.Secure("Password: ")

	body := struct {
		Password string `json:"password"`
	}{ password, }
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url(addr, "/v1/auth/ldap/login/%s", username),
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}

	return authenticate(req)
}
