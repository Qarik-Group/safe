package rc

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ghodss/yaml"
)

type Target struct {
	URL      string   `yaml:"url"`
	Token    string   `yaml:"token"`
	Backends []string `yaml:"backends"`
}

type Config struct {
	Version string             `yaml:"version"`
	Target  string             `yaml:"target"`
	Targets map[string]*Target `yaml:"targets"`
}

type ConfigV1 struct {
	Current string                 `yaml:"current"`
	Targets map[string]interface{} `yaml:"targets"`
	Aliases map[string]string      `yaml:"aliases"`
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
		if tok, ok := v1.Targets[name]; ok {
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

	if t.Token != nil {
		return t.URL, t.Token.(string), nil
	}

	return url, "", nil
}

func Apply() Config {
	var c Config

	b, err := ioutil.ReadFile(saferc())
	if err == nil {
		yaml.Unmarshal(b, &c)
		if c.Version == "" {
			var v1 ConfigV1
			yaml.Unmarshal(b, &v1)
			c = upgrade(v1)
		}
	}

	c.Apply()
	return c
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

func (c *Config) URL() string {
	if t, ok := c.Targets[c.Target]; ok {
		return t.URL
	}
	return ""
}
