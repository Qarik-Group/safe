package vault

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
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
	ProxyConf httpproxy.Config
}

func (n ProxyRouter) Proxy(req *http.Request) (*url.URL, error) {
	return n.ProxyConf.ProxyFunc()(req.URL)
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

	knownHostsFile := getEnvironmentVariable("SAFE_KNOWN_HOSTS_FILE", "safe_known_hosts_file")
	skipHostKeyString := getEnvironmentVariable("SAFE_SKIP_HOST_KEY_VALIDATION", "safe_skip_host_key_validation")
	skipHostKeyValidation := true
	for _, falseString := range []string{"", "false", "no", "0"} {
		if skipHostKeyString == falseString {
			skipHostKeyValidation = false
			break
		}
	}

	oldHTTPProxy := httpProxy
	var err error
	if strings.HasPrefix(httpProxy, "ssh+socks5://") {
		httpProxy, err = openSOCKS5Helper(httpProxy, knownHostsFile, skipHostKeyValidation)
		if err != nil {
			return nil, err
		}
	}

	if strings.HasPrefix(httpsProxy, "ssh+socks5://") {
		if httpsProxy == oldHTTPProxy {
			httpsProxy = httpProxy
		} else {
			httpsProxy, err = openSOCKS5Helper(httpsProxy, knownHostsFile, skipHostKeyValidation)
			if err != nil {
				return nil, err
			}
		}
	}

	return &ProxyRouter{
		ProxyConf: httpproxy.Config{
			HTTPProxy:  httpProxy,
			HTTPSProxy: httpsProxy,
			NoProxy:    noProxy,
		},
	}, nil
}

func openSOCKS5Helper(toOpen, knownHostsFile string, skipHostKeyValidation bool) (string, error) {
	u, err := url.Parse(toOpen)
	if err != nil {
		return "", fmt.Errorf("Could not parse proxy URL (%s): %s", toOpen, err)
	}

	if u.User == nil {
		return "", fmt.Errorf("No user provided for SSH proxy")
	}

	if u.Port() == "" {
		u.Host = u.Host + ":22"
	}

	privateKeyPath := u.Query()["private-key"]

	if u.Path != "" && u.Path != "/" {
		privateKeyPath = append(privateKeyPath, u.Path)
	}

	if len(privateKeyPath) == 0 {
		return "", fmt.Errorf("No private key path provided")
	}

	if len(privateKeyPath) > 1 {
		return "", fmt.Errorf("More than one private key provided")
	}

	privateKeyContents, err := ioutil.ReadFile(privateKeyPath[0])
	if err != nil {
		return "", fmt.Errorf("Could not read private key file (%s): %s", privateKeyPath[0], err)
	}

	sshClient, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:                  u.Host,
		User:                  u.User.Username(),
		PrivateKey:            privateKeyContents,
		KnownHostsFile:        knownHostsFile,
		SkipHostKeyValidation: skipHostKeyValidation,
	})
	if err != nil {
		return "", fmt.Errorf("Could not start SSH tunnel: %s", err)
	}

	socks5Addr, err := StartSOCKS5Server(sshClient.Dial)
	if err != nil {
		return "", fmt.Errorf("Could not start SOCKS5 Server: %s", err)
	}

	return fmt.Sprintf("socks5://%s", socks5Addr), nil
}

func getEnvironmentVariable(variables ...string) string {
	for _, v := range variables {
		ret := os.Getenv(v)
		if ret != "" {
			return ret
		}
	}

	return ""
}

//SOCKS5SSHConfig contains configuration variables for setting up a SOCKS5
//proxy to be tunneled through an SSH connection.
type SOCKS5SSHConfig struct {
	Host                  string
	User                  string
	PrivateKey            []byte
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
			if os.Getenv("HOME") == "" {
				return nil, fmt.Errorf("No home directory set and no known hosts file explicitly given; cannot validate host key")
			}
			conf.KnownHostsFile = fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME"))
		}

		hostKeyCallback, err = knownHostsPromptCallback(conf.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("Error opening known_hosts file at `%s': %s", conf.KnownHostsFile, err)
		}
	}

	privateKeySigner, err := ssh.ParsePrivateKey(conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Could not create signer for private key: %s", err)
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

	go func() {
		err = socks5Server.Serve(socks5Listener)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SOCKS5 proxy error: %s\n", err)
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

			hostKeyConflictError := `
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %[1]s key sent by the remote host is
%[2]s.
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
%[3]s key fingerprint is %[4]s
Are you sure you want to continue connecting (yes/no)? `, hostname, remote.String(), key.Type(), ssh.FingerprintSHA256(key))

	var response string
	fmt.Scanln(&response)
	for response != "yes" && response != "no" {
		fmt.Fprintf(os.Stderr, "Please type 'yes' or 'no': ")
		fmt.Scanln(&response)
	}

	return response == "yes"
}

func writeKnownHosts(knownHostsFile, hostname string, key ssh.PublicKey) error {
	normalizedHostname := knownhosts.Normalize(hostname)
	f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("Could not open `%s' for reading: %s", knownHostsFile, err)
	}

	fileInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("Could no retrieve info for file `%s'")
	}

	if fileInfo.Size() != 0 {
		//Let's make sure we're writing to a new line...
		_, err := f.Seek(-1, 2)
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
	}

	newKnownHostsLine := knownhosts.Line([]string{normalizedHostname}, key)
	_, err = f.WriteString(newKnownHostsLine + "\n")
	if err != nil {
		return fmt.Errorf("Error when writing to `%s': %s", knownHostsFile, err)
	}

	fmt.Fprintf(os.Stderr, "Warning: Permanently added '%s' (%s) to the list of known hosts.\n", hostname, key.Type())
	return nil
}

func noopDialContext(base func(string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return base(network, addr)
	}
}
