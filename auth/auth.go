package auth

import (
	"net/http"
	"fmt"
	"crypto/tls"
	"os"
	"encoding/json"
	"io/ioutil"
)

func url(url, f string, args ...interface{}) string {
	return url + fmt.Sprintf(f, args...)
}

func authenticate(req *http.Request) (string, error) {
	client := &http.Client{
		Transport:  &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: os.Getenv("VAULT_SKIP_VERIFY") != "",
			},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
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
