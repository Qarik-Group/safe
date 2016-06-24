package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

func authurl(base, f string, args ...interface{}) string {
	return base + fmt.Sprintf(f, args...)
}

func authenticate(req *http.Request) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: os.Getenv("VAULT_SKIP_VERIFY") != "",
			},
		},
	}

	var (
		body []byte
		err  error
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
