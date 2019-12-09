package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/starkandwayne/safe/prompt"
)

func UserPass(addr, path string) (string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		path = "userpass"
	}

	username := prompt.Normal("Username: ")
	password := prompt.Secure("Password: ")

	body := struct {
		Password string `json:"password"`
	}{password}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", authurl(addr, "/v1/auth/%s/login/%s", path, username),
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}

	return authenticate(req)
}
