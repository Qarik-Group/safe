package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

func (v *Vault) SealKeys() (int, error) {
	req, err := http.NewRequest("GET", v.url("/v1/sys/seal-status"), nil)
	if err != nil {
		return 0, err
	}
	res, err := v.request(req)
	if err != nil {
		return 0, err
	}

	if res.StatusCode != 200 {
		return 0, fmt.Errorf("received HTTP %d response (to /v1/sys/seal-status)", res.StatusCode)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	var data = struct {
		Keys int `json:"t"`
	}{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		return 0, err
	}
	return data.Keys, nil
}

func (v *Vault) Seal() (bool, error) {
	req, err := http.NewRequest("PUT", v.url("/v1/sys/seal"), nil)
	if err != nil {
		return false, err
	}
	res, err := v.request(req)
	if err != nil {
		return false, err
	}

	if res.StatusCode == 500 {
		if b, err := ioutil.ReadAll(res.Body); err == nil {
			if matched, _ := regexp.Match("cannot seal when in standby mode", b); matched {
				return false, nil
			}
		}
	}
	if res.StatusCode != 204 {
		return false, fmt.Errorf("received HTTP %d response", res.StatusCode)
	}
	return true, nil
}

func (v *Vault) Unseal(keys []string) error {
	req, err := http.NewRequest("PUT", v.url("/v1/sys/unseal"), strings.NewReader(`{"reset":true}`))
	if err != nil {
		return err
	}
	res, err := v.request(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("received HTTP %d response", res.StatusCode)
	}

	for _, k := range keys {
		req, err := http.NewRequest("PUT", v.url("/v1/sys/unseal"), strings.NewReader(`{"key":"`+k+`"}`))
		if err != nil {
			return err
		}
		res, err := v.request(req)
		if err != nil {
			return err
		}

		if res.StatusCode != 200 {
			return fmt.Errorf("received HTTP %d response", res.StatusCode)
		}
	}
	return nil
}
