package vault

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
	"github.com/starkandwayne/safe/prompt"
	"golang.org/x/crypto/ssh/terminal"
)

var termState *terminal.State

func (v *Vault) cancelRekey() {
	if termState != nil {
		terminal.Restore(int(os.Stdin.Fd()), termState)
	}
	err := v.client.Client.RekeyCancel()
	if err != nil {
		ansi.Fprintf(os.Stderr, "Failed to cancel rekey process: %s\n", err.Error())
		return
	}

	ansi.Fprintf(os.Stderr, "@y{Vault rekey canceled successfully}\n")
}

func (v *Vault) ReKey(unsealKeyCount, numToUnseal int, pgpKeys []string) ([]string, error) {
	err := v.client.Client.RekeyCancel()
	if err != nil {
		return nil, fmt.Errorf("An error occurred when trying to cancel potentially preexisting rekey: %s", err)
	}

	backup := len(pgpKeys) > 0
	rekey, err := v.client.Client.NewRekey(vaultkv.RekeyConfig{
		Shares:    unsealKeyCount,
		Threshold: numToUnseal,
		PGPKeys:   pgpKeys,
		Backup:    backup,
	})
	if err != nil {
		return nil, fmt.Errorf("An error occurred when starting a new rekey operation: %s", err)
	}

	// we successfully started a rekey, we should now cancel on failure, unless we finish rekeying
	var shouldCancelRekey = true
	defer func() {
		if shouldCancelRekey {
			v.cancelRekey()
		}
	}()
	sighandler := make(chan os.Signal, 4)
	signal.Ignore(os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	signal.Notify(sighandler, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for _ = range sighandler {
			v.cancelRekey()
			os.Exit(1)
		}
	}()

	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		termState, err = terminal.GetState(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
	}

	givenKeys := make([]string, rekey.Remaining())

	for i := 0; i < len(givenKeys); i++ {
		givenKeys[i] = prompt.Secure("Unseal Key %d: ", i+1)
	}

	rekeyDone, err := rekey.Submit(givenKeys...)
	if err != nil {
		return nil, fmt.Errorf("Key submission failed: %s", err)
	}
	if !rekeyDone {
		return nil, fmt.Errorf("The rekey did not finish (is somebody else trying to rekey at the same time?)")
	}

	// vault should be rekeyed by here, as our progress met the requirement
	shouldCancelRekey = false
	signal.Stop(sighandler)

	return rekey.Keys(), nil
}
