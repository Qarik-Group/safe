package auth

import (
	"fmt"
	"net/http/httputil"
	"encoding/json"
	"net/http"
	"strings"
	"os"

	"github.com/starkandwayne/safe/prompt"
)

func Github(addr string) (string, error) {
	access := prompt.Secure("Github Personal Access Token: ")

	body := struct {
		Token string `json:"token"`
	}{access}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", authurl(addr, "/v1/auth/github/login"),
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
