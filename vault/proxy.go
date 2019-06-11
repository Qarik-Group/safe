package vault

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	socks5 "github.com/armon/go-socks5"
	isatty "github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/http/httpproxy"
)

type ProxyRouter struct {
	proxyConf httpproxy.Config
}

func (n ProxyRouter) Proxy(req *http.Request) (*url.URL, error) {
	return n.proxyConf.ProxyFunc()(req.URL)
}

func NewProxyRouter() (*ProxyRouter, error) {
	httpProxy := getEnvironmentVariable("HTTP_PROXY", "http_proxy")
	httpsProxy := getEnvironmentVariable("HTTPS_PROXY", "https_proxy")

	allProxy := getEnvironmentVariable("SAFE_ALL_PROXY", "safe_all_proxy")
	if allProxy != "" {
		httpProxy = allProxy
		httpsProxy = allProxy
	}

	noProxy := getEnvironmentVariable("NO_PROXY", "no_proxy")

	knownHostsFile := getEnvironmentVariable("KNOWN_HOSTS_FILE", "known_hosts_file")
	skipHostKeyString := getEnvironmentVariable("SKIP_HOST_KEY_VALIDATION", "skip_host_key_validation")
	skipHostKeyValidation := skipHostKeyString != "" && skipHostKeyString != "false"

	var tunnelsToOpen []*string
	if strings.HasPrefix(httpProxy, "ssh+socks5://") {
		tunnelsToOpen = append(tunnelsToOpen, &httpProxy)
	}

	if strings.HasPrefix(httpsProxy, "ssh+socks5://") {
		tunnelsToOpen = append(tunnelsToOpen, &httpsProxy)
	}

	for i := range tunnelsToOpen {
		//If we haven't already opened a proxy for this...
		if i == 0 || *(tunnelsToOpen[i]) != *(tunnelsToOpen[i-1]) {
			//Let's open a proxy!
			u, err := url.Parse(*(tunnelsToOpen[i]))
			if err != nil {
				return nil, fmt.Errorf("Could not parse proxy URL (%s): %s", *tunnelsToOpen[i], err)
			}

			if u.User == nil {
				return nil, fmt.Errorf("No user provided for SSH proxy")
			}

			sshClient, err := StartSSHTunnel(SOCKS5SSHConfig{
				Host:                  u.Host,
				User:                  u.User.Username(),
				PrivateKey:            u.Path,
				KnownHostsFile:        knownHostsFile,
				SkipHostKeyValidation: skipHostKeyValidation,
			})
			if err != nil {
				return nil, fmt.Errorf("Could not start SSH tunnel: %s", err)
			}

			socks5Addr, err := StartSOCKS5Server(sshClient.Dial)
			if err != nil {
				return nil, fmt.Errorf("Could not start SOCKS5 Server: %s", err)
			}
			*tunnelsToOpen[i] = fmt.Sprintf("socks5://%s", socks5Addr)
		} else {
			//Let's get the address of the already opened proxy
			*tunnelsToOpen[i] = *tunnelsToOpen[i-1]
		}
	}

	return &ProxyRouter{
		proxyConf: httpproxy.Config{
			HTTPProxy:  httpProxy,
			HTTPSProxy: httpsProxy,
			NoProxy:    noProxy,
		},
	}, nil
}

func getEnvironmentVariable(variables ...string) string {
	var ret string
	for _, v := range variables {
		ret := os.Getenv(v)
		if ret != "" {
			break
		}
	}

	return ret
}

//SOCKS5SSHConfig contains configuration variables for setting up a SOCKS5
//proxy to be tunneled through an SSH connection.
type SOCKS5SSHConfig struct {
	Host                  string
	User                  string
	PrivateKey            string
	KnownHostsFile        string
	SkipHostKeyValidation bool
}

//StartSSHTunnel makes an SSH connection according to the given config. It
// returns an SSH client if it was successful and an error otherwise.
func StartSSHTunnel(conf SOCKS5SSHConfig) (*ssh.Client, error) {
	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	var err error

	if !conf.SkipHostKeyValidation {
		if conf.KnownHostsFile == "" {
			conf.KnownHostsFile = fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME"))
		}

		hostKeyCallback, err = knownHostsPromptCallback(conf.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("Error opening known_hosts file at `%s': %s", conf.KnownHostsFile, err)
		}
	}
	privateKeySigner, err := ssh.NewSignerFromKey(conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Could not create signer for private key")
	}

	sshConfig := &ssh.ClientConfig{
		User:            conf.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(privateKeySigner)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	return ssh.Dial("tcp", conf.Host, sshConfig)
}

//StartSOCKS5SSH makes an SSH connection according to the given config, starts
//a local SOCKS5 server on a random port, and then returns the proxy
//address if the connection was successful and an error if it was unsuccessful.
func StartSOCKS5Server(dialFn func(string, string) (net.Conn, error)) (string, error) {
	socks5Server, err := socks5.New(&socks5.Config{
		Dial: noopDialContext(dialFn),
	})
	if err != nil {
		return "", fmt.Errorf("Error starting local SOCKS5 server: %s", err)
	}

	socks5Listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("Error starting local SOCKS5 server: %s", err)
	}

	//TODO: Put this on another thread. Get error somehow?
	go func() {
		err = socks5Server.Serve(socks5Listener)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SOCKS5 proxy error: %s", err)
		}
	}()

	return socks5Listener.Addr().String(), nil
}

func knownHostsPromptCallback(knownHostsFile string) (ssh.HostKeyCallback, error) {
	tmpCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("Could not handle known hosts file: %s", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err = tmpCallback(hostname, remote, key)
		//If the base check is fine, then we just let the ssh request carry on
		if err == nil {
			return nil
		}

		//If we're here, we got some sort of error
		//Let's check if it was because the key wasn't trusted
		errAsKeyError, isKeyError := err.(*knownhosts.KeyError)
		if !isKeyError {
			return err
		}

		//If the error has hostnames listed under Want, it means that there was
		// a conflicting host key
		if len(errAsKeyError.Want) > 0 {
			wantedKey := errAsKeyError.Want[0]
			for _, k := range errAsKeyError.Want {
				if wantedKey.Key.Type() == key.Type() {
					wantedKey = k
				}
			}

			hostKeyConflictError := `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %[1]s key sent by the remote host is
SHA256:%[2]s.
Please contact your system administrator.
Add correct host key in %[3]s to get rid of this message.
Offending %[1]s key in %[3]s:%[4]d
%[1]s host key for %[5]s has changed and safe uses strict checking.
Host key verification failed.
`
			return fmt.Errorf(hostKeyConflictError,
				key.Type(), ssh.FingerprintSHA256(key), knownHostsFile, wantedKey.Line, hostname)
		}

		//If not, then the key doesn't exist in the host key file
		//Let's see if we can ask the user if they want to add it
		if !isatty.IsTerminal(os.Stderr.Fd()) || !promptAddNewKnownHost(hostname, remote, key) {
			//If its not a terminal or the user declined, we're rejecting it
			return fmt.Errorf("Host key verification failed: %s", err)
		}

		err = writeKnownHosts(knownHostsFile, hostname, key)
		if err != nil {
			return err
		}

		return nil
	}, nil
}

func promptAddNewKnownHost(hostname string, remote net.Addr, key ssh.PublicKey) bool {
	//Otherwise, let's ask the user
	fmt.Fprintf(os.Stderr, `The authenticity of host '%[1]s (%[2]s)' can't be established.
%[3]s key fingerprint is SHA256:%[4]s
Are you sure you want to continue connecting (yes/no)? `, hostname, remote.String(), key.Type(), ssh.FingerprintSHA256(key))

	var response string
	fmt.Scanln(&response)
	for response != "yes" && response != "no" {
		fmt.Fprintf(os.Stderr, "Please type 'yes' or 'no': ")
		fmt.Scanln(&response)
	}

	return response == "no"
}

func writeKnownHosts(knownHostsFile, hostname string, key ssh.PublicKey) error {
	normalizedHostname := knownhosts.Normalize(hostname)
	f, err := os.Open(knownHostsFile)
	if err != nil {
		return fmt.Errorf("Could not open `%s' for reading: %s", knownHostsFile, err)
	}
	//Let's make sure we're writing to a new line...
	_, err = f.Seek(-1, 2)
	if err != nil {
		return fmt.Errorf("Error when seeking to end of `%s': %s", knownHostsFile, err)
	}

	lastByte := make([]byte, 1)
	_, err = f.Read(lastByte)
	if err != nil {
		return fmt.Errorf("Error when reading from `%s': %s", knownHostsFile, err)
	}

	if !bytes.Equal(lastByte, []byte("\n")) {
		//Need to append a newline
		_, err = f.Write([]byte("\n"))
		if err != nil {
			return fmt.Errorf("Error when writing to `%s': %s", knownHostsFile, err)
		}
	}

	newKnownHostsLine := knownhosts.Line([]string{normalizedHostname}, key)
	_, err = f.WriteString(newKnownHostsLine)
	if err != nil {
		return fmt.Errorf("Error when writing to `%s': %s", knownHostsFile, err)
	}
	return nil
}

func noopDialContext(base func(string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return base(network, addr)
	}
}
