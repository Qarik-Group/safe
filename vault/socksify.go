package vault

import (
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/cloudfoundry/socks5-proxy"
	goproxy "golang.org/x/net/proxy"
)

type DialFunc func(network, address string) (net.Conn, error)

type ProxyDialer interface {
	Dialer(string, string, string) (proxy.DialFunc, error)
}

func (f DialFunc) Dial(network, address string) (net.Conn, error) { return f(network, address) }

func SOCKS5DialFuncFromEnvironment(origDialer DialFunc, socks5Proxy ProxyDialer) DialFunc {
	allProxy := os.Getenv("SAFE_PROXY")
	if len(allProxy) == 0 {
		return origDialer
	}

	if strings.HasPrefix(allProxy, "ssh+") {
		allProxy = strings.TrimPrefix(allProxy, "ssh+")

		proxyURL, err := url.Parse(allProxy)
		if err != nil {
			return origDialer
		}

		queryMap, err := url.ParseQuery(proxyURL.RawQuery)
		if err != nil {
			return origDialer
		}

		proxySSHKeyPath, ok := queryMap["private-key"]
		if !ok {
			return origDialer
		}

		username := ""
		if proxyURL.User != nil {
			username = proxyURL.User.Username()
		}

		if len(proxySSHKeyPath) == 0 {
			return origDialer
		}

		proxySSHKey, err := ioutil.ReadFile(proxySSHKeyPath[0])
		if err != nil {
			return origDialer
		}

		var (
			dialer proxy.DialFunc
			mut    sync.RWMutex
		)
		return func(network, address string) (net.Conn, error) {
			mut.RLock()
			haveDialer := dialer != nil
			mut.RUnlock()

			if haveDialer {
				return dialer(network, address)
			}

			mut.Lock()
			defer mut.Unlock()
			if dialer == nil {
				proxyDialer, err := socks5Proxy.Dialer(username, string(proxySSHKey), proxyURL.Host)
				if err != nil {
					return nil, err
				}
				dialer = proxyDialer
			}
			return dialer(network, address)
		}
	}

	proxyURL, err := url.Parse(allProxy)
	if err != nil {
		return origDialer
	}

	proxy, err := goproxy.FromURL(proxyURL, origDialer)
	if err != nil {
		return origDialer
	}

	noProxy := os.Getenv("no_proxy")
	if len(noProxy) == 0 {
		return proxy.Dial
	}

	perHost := goproxy.NewPerHost(proxy, origDialer)
	perHost.AddFromString(noProxy)

	return perHost.Dial
}
