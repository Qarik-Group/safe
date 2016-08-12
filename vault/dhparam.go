package vault

import (
	"fmt"
	"os"
	"os/exec"
)

func genDHParam(bits int) (string, error) {
	cmd := exec.Command("openssl", "dhparam", fmt.Sprintf("%d", bits))
	cmd.Stderr = os.Stderr

	// output runs command and returns output
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
