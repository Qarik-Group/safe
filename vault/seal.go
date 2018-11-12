package vault

import (
	"github.com/cloudfoundry-community/vaultkv"
)

//SealKeys returns the threshold for unsealing the vault
func (v *Vault) SealKeys() (int, error) {
	state, err := v.client.Client.SealStatus()
	if err != nil {
		return 0, err
	}

	return state.Threshold, nil
}

func (v *Vault) Seal() (bool, error) {
	err := v.client.Client.Seal()
	ret := err == nil
	if vaultkv.IsErrStandby(err) {
		err = nil
	}

	return ret, err
}

func (v *Vault) Unseal(keys []string) error {
	err := v.client.Client.ResetUnseal()
	if err != nil {
		return err
	}

	for _, key := range keys {
		state, err := v.client.Client.Unseal(key)
		if err != nil {
			return err
		}

		if state.Sealed == false {
			break
		}
	}
	return nil
}
