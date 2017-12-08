package vault

import (
	"fmt"
	"net/http"
)

func (v *Vault) RenewLease() error {
	req, err := http.NewRequest("POST", v.url("/v1/auth/token/renew-self"), nil)
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

	return nil
}
