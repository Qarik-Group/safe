package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func (v *Vault) Init(nkeys, threshold int) ([]string, string, error) {
	if threshold > nkeys {
		return nil, "", fmt.Errorf("cannot require %d/%d keys -- threshold is too high!", threshold, nkeys)
	}

	in := struct {
		Keys      int `json:"secret_shares"`
		Threshold int `json:"secret_threshold"`
	}{
		Keys:      nkeys,
		Threshold: threshold,
	}
	b, err := json.Marshal(&in)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequest("POST", v.url("/v1/sys/init"), bytes.NewReader(b))
	if err != nil {
		return nil, "", err
	}

	res, err := v.request(req)
	if err != nil {
		return nil, "", err
	}

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}

	var out struct {
		Keys  []string `json:"keys_base64"`
		Token string   `json:"root_token"`

		Errors []string `json:"errors"`
	}
	err = json.Unmarshal(b, &out)
	if err != nil {
		return nil, "", err
	}

	if res.StatusCode != 200 {
		if len(out.Errors) > 0 {
			return nil, "", fmt.Errorf("%s", out.Errors[0])
		} else {
			return nil, "", fmt.Errorf("an unspecified error has occurred.")
		}
	}

	return out.Keys, out.Token, nil
}
