package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
)

func (v *Vault) Strongbox() (map[string]string, error) {
	m := make(map[string]string)

	u, err := url.Parse(v.URL)
	if err != nil {
		return m, err
	}

	c := &http.Client{}
	re := regexp.MustCompile(`:[0-9]+$`)

	uri := "http://" + re.ReplaceAllString(u.Host, "") + ":8484/strongbox"
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return m, err
	}

	res, err := c.Do(req)
	if err != nil {
		return m, err
	}

	if res.StatusCode != 200 {
		return m, fmt.Errorf("received an HTTP %d response from %s", res.StatusCode, uri)
	}

	b, err := ioutil.ReadAll(res.Body)
	err = json.Unmarshal(b, &m)
	return m, err
}
