package vault

import (
	"fmt"
	"strings"

	"github.com/cloudfoundry-community/vaultkv"
)

func (v *Vault) AddMount(path string, version int) error {
	return v.Client().Client.EnableSecretsMount(path, vaultkv.Mount{
		Type:        "kv",
		Description: fmt.Sprintf("A KV v%d Mount created by safe", version),
		Options:     vaultkv.KVMountOptions{}.WithVersion(version),
	})
}

func (v *Vault) ListMounts() (mounts []string, err error) {
	var mountMap map[string]vaultkv.Mount
	mountMap, err = v.Client().Client.ListMounts()
	if err != nil {
		return
	}

	for k := range mountMap {
		mounts = append(mounts, k)
	}

	return
}

func (v *Vault) MountExists(path string) (bool, error) {
	mounts, err := v.ListMounts()
	if err != nil {
		return false, err
	}

	for _, mount := range mounts {
		if strings.Trim(path, "/") == strings.Trim(mount, "/") {
			return true, nil
		}
	}
	return false, nil
}
