package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/starkandwayne/safe/vault"
)

func shouldDebug() bool {
	d := strings.ToLower(os.Getenv("DEBUG"))
	return d != "" && d != "false" && d != "0" && d != "no" && d != "off"
}

func authurl(base, f string, args ...interface{}) string {
	return base + fmt.Sprintf(f, args...)
}

func authenticate(req *http.Request) (string, error) {
	proxyRouter, err := vault.NewProxyRouter()
	if err != nil {
		return "", fmt.Errorf("Error setting up proxy: %s", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: os.Getenv("VAULT_SKIP_VERIFY") != "",
			},
			Proxy:               proxyRouter.Proxy,
			MaxIdleConnsPerHost: 100,
		},
	}

	var (
		body []byte
		res  *http.Response
	)
	if req.Body != nil {
		body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
	}

	for i := 0; i < 10; i++ {
		if req.Body != nil {
			req.Body = ioutil.NopCloser(bytes.NewReader(body))
		}
		res, err = client.Do(req)
		if err != nil {
			return "", err
		}

		if shouldDebug() {
			r, _ := httputil.DumpResponse(res, true)
			fmt.Fprintf(os.Stderr, "Response:\n%s\n----------------\n", r)
		}
		// Vault returns a 307 to redirect during HA / Auth
		if res.StatusCode == 307 {
			// Note: this does not handle relative Location headers
			u, err := url.Parse(res.Header.Get("Location"))
			if err != nil {
				return "", err
			}
			req.URL = u
			// ... and try again.
			continue
		}
		break
	}

	if res.StatusCode != 200 {
		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		var e struct {
			Errors []string `json:"errors"`
		}
		if err = json.Unmarshal(b, &e); err == nil && len(e.Errors) > 0 {
			/* did our Github auth token fail? */
			if strings.Contains(e.Errors[0], "401 Bad credentials") {
				return "", fmt.Errorf("authentication failed.")
			}
			return "", fmt.Errorf("Vault API errored: %s", e.Errors[0])
		}

		return "", fmt.Errorf("API %s", res.Status)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var raw map[string]interface{}
	if err = json.Unmarshal(b, &raw); err != nil {
		return "", err
	}

	if authdata, ok := raw["auth"]; ok {
		if data, ok := authdata.(map[string]interface{}); ok {
			if tok, ok := data["client_token"]; ok {
				if s, ok := tok.(string); ok {
					return s, nil
				}
			}
		}
	}

	return "", nil
}
