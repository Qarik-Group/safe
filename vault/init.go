package vault

import (
	"github.com/cloudfoundry-community/vaultkv"
)

func (v *Vault) Init(nkeys, threshold int) ([]string, string, error) {
	out, err := v.client.Client.InitVault(vaultkv.InitConfig{
		Shares:    nkeys,
		Threshold: threshold,
	})

	if err != nil {
		return nil, "", err
	}

	return out.Keys, out.RootToken, nil
}
