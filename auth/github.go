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

func Github(addr, path string) (string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		path = "github"
	}

	access := prompt.Secure("Github Personal Access Token: ")

	body := struct {
		Token string `json:"token"`
	}{access}
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
