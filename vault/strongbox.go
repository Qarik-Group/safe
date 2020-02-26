package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
)

func (v *Vault) Strongbox() (map[string]string, error) {
	m := make(map[string]string)

	u := *v.client.Client.VaultURL

	c := v.client.Client.Client
	uri := StrongboxURL(&u)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return m, err
	}

	if v.debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error dumping Strongbox request: %s\n", err)
		}

		fmt.Fprintf(os.Stderr, "Request:\n%s\n", dump)
	}

	res, err := c.Do(req)
	if err != nil {
		return m, err
	}
	defer res.Body.Close()

	if v.debug {
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error dumping Strongbox response: %s\n", err)
		}

		fmt.Fprintf(os.Stderr, "Response:\n%s\n", dump)
	}

	if res.StatusCode != 200 {
		return m, fmt.Errorf("received an HTTP %d response from %s", res.StatusCode, uri)
	}

	b, err := ioutil.ReadAll(res.Body)
	err = json.Unmarshal(b, &m)
	return m, err
}

func StrongboxURL(vaultURL *url.URL) string {
	re := regexp.MustCompile(`:[0-9]+$`)
	return "http://" + re.ReplaceAllString(vaultURL.Host, "") + ":8484/strongbox"
}
