package rc

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/starkandwayne/goutils/botta"
	"github.com/starkandwayne/safe/vault"
	"gopkg.in/yaml.v2"
)

var portStripper *regexp.Regexp
var hostReplacer *regexp.Regexp

func init() {
	portStripper = regexp.MustCompile(":[0-9]*$")
	hostReplacer = regexp.MustCompile("^[^:]+")
}

type Target struct {
	URL      string      `yaml:"url"`
	Token    interface{} `yaml:"token"`
	Active   interface{} `yaml:"active"`
	Backends []string    `yaml:"backends"`
}

type Config struct {
	Version   string             `yaml:"version"`
	HATimeout int                `yaml:"ha_timeout"`
	Target    string             `yaml:"target"`
	Targets   map[string]*Target `yaml:"targets"`
}

type ConfigV1 struct {
	Current string                 `yaml:"Current"`
	Targets map[string]interface{} `yaml:"Targets"`
	Aliases map[string]string      `yaml:"Aliases"`
}

func SwapHost(u *url.URL, host string) string {
	u.Host = hostReplacer.ReplaceAllString(u.Host, host)
	return u.String()
}

func saferc() string {
	return fmt.Sprintf("%s/.saferc", os.Getenv("HOME"))
}

func svtoken() string {
	return fmt.Sprintf("%s/.svtoken", os.Getenv("HOME"))
}

func upgrade(v1 ConfigV1) Config {
	c := Config{}
	c.Version = "2"
	c.Target = v1.Current
	c.Targets = make(map[string]*Target)
	for name, url := range v1.Aliases {
		c.Targets[name] = &Target{
			URL: url,
		}
		if tok, ok := v1.Targets[url]; ok {
			c.Targets[name].Token = tok
		}
	}
	return c
}

func (c *Config) credentials() (string, string, error) {
	if c.Target == "" {
		return "", "", nil
	}

	t, ok := c.Targets[c.Target]
	if !ok {
		return "", "", fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Target)
	}

	addr := t.URL
	if t.Active != nil {
		u, err := url.Parse(t.URL)
		if err != nil {
			return "", "", err
		}
		os.Setenv("VAULT_HOSTNAME", u.Host)
		addr = SwapHost(u, t.Active.(string))
	}

	if t.Token != nil {
		return addr, t.Token.(string), nil
	}

	return addr, "", nil
}

func Apply(sync bool) Config {
	tr := struct {
		Version string `yaml:"version"`
	}{}
	var c Config

	b, err := ioutil.ReadFile(saferc())
	if err == nil {
		yaml.Unmarshal(b, &tr)
		if tr.Version == "" || tr.Version == "1" {
			/* legacy config; upgrade and persist to disk */
			var v1 ConfigV1
			yaml.Unmarshal(b, &v1)
			c = upgrade(v1)
			c.Write()

		} else {
			yaml.Unmarshal(b, &c)
		}
	}

	if c.HATimeout == 0 {
		c.HATimeout = 1
	}

	if sync {
		c.Sync()
	}
	c.Apply()
	return c
}

func (c *Config) Sync() {
	if t, ok := c.Targets[c.Target]; ok {
		var backends []string
		client := http.Client{
			Timeout: time.Duration(c.HATimeout) * time.Second,
		}
		botta.SetClient(&client)

		urls := c.VaultEndpoints()
		if len(urls) == 0 {
			urls = []string{t.URL}
		}

		for _, host := range urls {
			host = portStripper.ReplaceAllString(host, ":8500")
			req, err := botta.Get(host + "/v1/catalog/service/vault")
			if err != nil {
				continue
			}
			if vault.ShouldDebug() {
				r, _ := httputil.DumpRequest(req, true)
				fmt.Fprintf(os.Stderr, "Request:\n%s\n----------------\n", r)
			}

			r, err := botta.Client().Do(req)
			if err != nil {
				continue
			}
			if vault.ShouldDebug() {
				dump, _ := httputil.DumpResponse(r, true)
				fmt.Fprintf(os.Stderr, "Response:\n%s\n----------------\n", dump)
			}
			res, err := botta.ParseResponse(r)
			if err != nil {
				continue
			}

			objs, err := res.ArrayVal("$")
			if err != nil {
				continue
			}
			for _, e := range objs {
				if obj, ok := e.(map[string]interface{}); ok {
					var addr string
					if addr, ok = obj["Address"].(string); !ok {
						continue
					}
					if addr == "" {
						continue
					}

					backends = append(backends, addr)

					if tags, ok := obj["ServiceTags"].([]interface{}); ok {
						for _, tag := range tags {
							if tag == "active" {
								t.Active = addr
							}
						}
					}
				}
			}

			if len(backends) > 0 {
				t.Backends = backends
			}
			break
		}
		c.Write()
	}
}

func (c *Config) Write() error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(saferc(), b, 0600)
	if err != nil {
		return err
	}

	url, token, err := c.credentials()
	if err != nil {
		return err
	}

	b, err = yaml.Marshal(
		struct {
			URL   string `json:"vault"`
			Token string `json:"token"`
		}{url, token})
	if err != nil {
		return err
	}

	return ioutil.WriteFile(svtoken(), b, 0600)
}

func (c *Config) Apply() error {
	url, token, err := c.credentials()
	if err != nil {
		return err
	}

	if url != "" {
		os.Setenv("VAULT_ADDR", url)
		os.Setenv("VAULT_TOKEN", token)
	} else {
		if os.Getenv("VAULT_TOKEN") == "" {
			tokenFile := fmt.Sprintf("%s/.vault-token", os.Getenv("HOME"))
			b, err := ioutil.ReadFile(tokenFile)
			if err == nil {
				os.Setenv("VAULT_TOKEN", strings.TrimSpace(string(b)))
			}
		}
	}
	return nil
}

func (c *Config) SetCurrent(alias string) error {
	if _, ok := c.Targets[alias]; ok {
		c.Target = alias
		return nil
	}
	return fmt.Errorf("Unknown target '%s'", alias)
}

func (c *Config) SetTarget(alias, url string) error {
	// FIXME: Not possible to have error, remove
	if c.Targets == nil {
		c.Targets = make(map[string]*Target)
	}
	c.Targets[alias] = &Target{
		URL: url,
	}
	c.Target = alias
	return nil
}

func (c *Config) SetToken(token string) error {
	if c.Target == "" {
		return fmt.Errorf("No target selected")
	}
	t, ok := c.Targets[c.Target]
	if !ok {
		return fmt.Errorf("Unknown target '%s'", c.Target)
	}
	t.Token = token
	return nil
}

// Helpers

func (c *Config) URL() string {
	if t, ok := c.Targets[c.Target]; ok {
		return t.URL
	}
	return ""
}

func (c *Config) DNS() []string {
	if t, ok := c.Targets[c.Target]; ok {
		// we use the backends from our last sync first
		l := make([]string, len(t.Backends))
		copy(l, t.Backends)

		// then we "fail back" to the actual endpoint URL
		// and pretend its the DNS endpoint (http/https no mo')
		u, err := url.Parse(t.URL)
		if err == nil {
			l = append(l, portStripper.ReplaceAllString(u.Host, ""))
		}
		return l
	}
	return []string{}
}

func (c *Config) VaultEndpoints() []string {
	if t, ok := c.Targets[c.Target]; ok {
		u, err := url.Parse(t.URL)
		if err != nil {
			return []string{}
		}

		l := make([]string, 0)
		for _, backend := range t.Backends {
			l = append(l, SwapHost(u, backend))
		}
		return l
	}
	return []string{}
}
