package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/starkandwayne/safe/prompt"
)

func AppRole(addr, path string) (string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		path = "approle"
	}

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

	req, err := http.NewRequest("POST", authurl(addr, "/v1/auth/%s/login", path),
		strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}

	if shouldDebug() {
		r, _ := httputil.DumpRequest(req, true)
		fmt.Fprintf(os.Stderr, "Request:\n%s\n----------------\n", r)
	}
	return authenticate(req)
}
