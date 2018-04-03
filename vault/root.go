package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func (v *Vault) NewRootToken(keys []string) (string, error) {
	// cancel any previous generate-root attmempts (get a new nonce!)
	req, err := http.NewRequest("DELETE", v.url("/v1/sys/generate-root/attempt"), nil)
	if err != nil {
		return "", err
	}
	res, err := v.request(req)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 204 {
		return "", fmt.Errorf("failed to cancel previous generate-root attempt: HTTP %d response", res.StatusCode)
	}

	// generate a 16-byte one-time password, base64-encoded
	otp := make([]byte, 16)
	otp64 := make([]byte, 24) // does this need pre-alloc'd?
	_, err = rand.Read(otp)
	if err != nil {
		return "", fmt.Errorf("unable to generate a one-time password: %s", err)
	}
	base64.StdEncoding.Encode(otp64, otp)

	// initiate a new generate-root attempt, with our one-time password in play
	req, err = http.NewRequest("PUT", v.url("/v1/sys/generate-root/attempt"), strings.NewReader(`{"otp":"`+string(otp64)+`"}`))
	if err != nil {
		return "", err
	}
	res, err = v.request(req)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("failed to start a new generate-root attempt: HTTP %d response", res.StatusCode)
	}

	//  extract the nonce for this generate-root attempt go-round
	var attempt struct {
		Nonce string `json:"nonce"`
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(b, &attempt)
	if err != nil {
		return "", err
	}

	encoded := ""
	for _, k := range keys {
		// for each key, pass back the nonce, provide the key, and go!
		payload := `{"key":"` + k + `","nonce":"` + attempt.Nonce + `"}`
		req, err := http.NewRequest("PUT", v.url("/v1/sys/generate-root/update"), strings.NewReader(payload))
		if err != nil {
			return "", err
		}
		res, err := v.request(req)
		if err != nil {
			return "", err
		}
		if res.StatusCode != 200 {
			return "", fmt.Errorf("failed to provide seal key to Vault: HTTP %d response", res.StatusCode)
		}

		// parse the response and save the encoded (token^otp) token
		var out struct {
			EncodedToken string `json:"encoded_token"`
			Complete     bool   `json:"complete"`
		}
		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}
		err = json.Unmarshal(b, &out)
		if err != nil {
			return "", err
		}
		if out.Complete {
			encoded = out.EncodedToken
		}
	}

	if encoded == "" {
		return "", fmt.Errorf("failed to generate new root token")
	}

	tok64 := []byte(encoded)
	tok := make([]byte, base64.StdEncoding.DecodedLen(len(tok64)))
	if len(tok64) != len(otp64) {
		return "", fmt.Errorf("failed to decode new root token")
	}

	base64.StdEncoding.Decode(tok, tok64)
	for i := 0; i < 16; i++ {
		tok[i] ^= otp[i]
	}

	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		tok[0], tok[1], tok[2], tok[3],
		tok[4], tok[5],
		tok[6], tok[7],
		tok[8], tok[9],
		tok[10], tok[11], tok[12], tok[13], tok[14], tok[15]), nil
}
