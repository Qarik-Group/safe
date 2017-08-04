package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/starkandwayne/safe/prompt"
)

func UserPass(addr string) (string, error) {
	username := prompt.Normal("Username: ")
	password := prompt.Secure("Password: ")

	body := struct {
		Password string `json:"password"`
	}{password}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", authurl(addr, "/v1/auth/userpass/login/%s", username),
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}

	return authenticate(req)
}
