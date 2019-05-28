package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/starkandwayne/safe/prompt"
)

func AppRole(addr string) (string, error) {
	role_id := prompt.Normal("Role ID: ")
	secret_id := prompt.Secure("Secret ID: ")

	body := struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}{role_id, secret_id}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", authurl(addr, "/v1/auth/approle/login"),
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}

	return authenticate(req)
}
