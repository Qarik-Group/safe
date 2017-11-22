package vault

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/jhunt/go-ansi"
	"github.com/starkandwayne/safe/prompt"
	"golang.org/x/crypto/ssh/terminal"
)

type RekeyOpts struct {
	SecretShares    int      `json:"secret_shares"`
	SecretThreshold int      `json:"secret_threshold"`
	PGPKeys         []string `json:"pgp_keys,omitempty"`
	Backup          bool     `json:"backup,omitempty"`
}

type RekeyUpdateOpts struct {
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
}

type RekeyResponse struct {
	Errors   []string `json:"errors"`
	Complete bool     `json:"complete"`
	Progress int      `json:"progress"`
	Required int      `json:"required"`
	Nonce    string   `json:"nonce"`
	Keys     []string `json:"keys"`
}

var shouldCancelRekey bool = false
var termState *terminal.State

func (v *Vault) cancelRekey() {
	if termState != nil {
		terminal.Restore(int(os.Stdin.Fd()), termState)
	}
	if shouldCancelRekey {
		resp, err := v.Curl("DELETE", "sys/rekey/init", nil)
		if err != nil {
			ansi.Fprintf(os.Stderr, "Failed to cancel rekey process (you may need to manually cancel to rekey next time): %s\n", err.Error())
			return
		}
		if resp.StatusCode >= 400 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ansi.Fprintf(os.Stderr, "Unable to read body from rekey cancelation response (you may need to manually cancel to rekey next time): %s\n", err)
				return
			}
			ansi.Fprintf(os.Stderr, "Failed to cancel rekey process (you may need to manually cancel to rekey next time): %s\n", body)
			return
		}
		ansi.Fprintf(os.Stderr, "@y{Vault rekey canceled successfully}\n")
	}
}

func (v *Vault) ReKey(unsealKeyCount, numToUnseal int, pgpKeys []string) ([]string, error) {
	backup := len(pgpKeys) > 0
	rekeyOptions := RekeyOpts{
		SecretShares:    unsealKeyCount,
		SecretThreshold: numToUnseal,
		PGPKeys:         pgpKeys,
		Backup:          backup,
	}
	rekeyJSON, err := json.Marshal(rekeyOptions)
	if err != nil {
		return nil, err
	}

	resp, err := v.Curl("POST", "sys/rekey/init", rekeyJSON)
	if err != nil {
		return nil, ansi.Errorf("Error re-keying Vault: %s", err.Error())
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	rekeyResp := RekeyResponse{}
	if err = json.Unmarshal(b, &rekeyResp); err != nil {
		return nil, err
	}

	if rekeyResp.Errors != nil && len(rekeyResp.Errors) > 0 {
		errorList, err := json.Marshal(rekeyResp.Errors)
		if err != nil {
			return nil, err
		}
		return nil, ansi.Errorf("Failed to start rekeying vault:\n%s", errorList)
	}
	if resp.StatusCode >= 400 {
		return nil, ansi.Errorf("Failed to start rekeying vault: %s\nServer said:\n%s", resp.Status, string(b))
	}

	// we successfully started a rekey, we should now cancel on failure, unless we finish rekeying
	shouldCancelRekey = true
	defer v.cancelRekey()
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
	for rekeyResp.Progress < rekeyResp.Required && rekeyResp.Complete == false {
		unsealKey := prompt.Secure("Unseal Key %d: ", rekeyResp.Progress+1)
		updateOpts := RekeyUpdateOpts{
			Key:   unsealKey,
			Nonce: rekeyResp.Nonce,
		}
		updateOptsJSON, err := json.Marshal(updateOpts)
		if err != nil {
			return nil, err
		}
		resp, err = v.Curl("POST", "sys/rekey/update", updateOptsJSON)
		if err != nil {
			return nil, ansi.Errorf("Error validating the Vault rekey: %s", err.Error())
		}

		b, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &rekeyResp); err != nil {
			return nil, err
		}

		if resp.StatusCode >= 400 {
			// grab 'errors' from json, print it out
			if rekeyResp.Errors != nil && len(rekeyResp.Errors) > 0 {
				errStr, err := json.Marshal(rekeyResp.Errors)
				if err != nil {
					return nil, err
				}
				return nil, ansi.Errorf("Error processing unseal key:\n%s", errStr)
			} else {
				return nil, ansi.Errorf("Error processing unseal key:\n%s", string(b))
			}
		}
	}
	// vault should be rekeyed by here, as our progress met the requirement
	shouldCancelRekey = false

	return rekeyResp.Keys, nil
}
