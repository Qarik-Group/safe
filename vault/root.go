package vault

import (
	"fmt"
)

func (v *Vault) NewRootToken(keys []string) (string, error) {
	// cancel any previous generate-root attempts (get a new nonce!)
	err := v.client.Client.GenerateRootCancel()
	if err != nil {
		return "", err
	}

	genRoot, err := v.client.Client.NewGenerateRoot()
	if err != nil {
		return "", err
	}

	done, err := genRoot.Submit(keys...)
	if err != nil {
		return "", err
	}
	if !done {
		return "", fmt.Errorf("Not enough keys were provided")
	}

	token, err := genRoot.RootToken()
	if err != nil {
		return "", err
	}

	return token, nil
}
