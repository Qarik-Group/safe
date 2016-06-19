package rc

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ghodss/yaml"
)

type Config struct {
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

func (c *Config) credentials() (string, string, error) {
	if c.Current == "" {
		return "", "", nil
	}

	url, ok := c.Aliases[c.Current]
	if !ok {
		return "", "", fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	t, ok := c.Targets[url]
	if !ok {
		return "", "", fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	token := ""
	if t != nil {
		token = t.(string)
	}

	return url, token, nil
}

func Apply() Config {
	var c Config

	b, err := ioutil.ReadFile(saferc())
	if err == nil {
		yaml.Unmarshal(b, &c)
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
	if _, ok := c.Aliases[alias]; ok {
		c.Current = alias
		return nil
	}
	return fmt.Errorf("Unknown target '%s'", alias)
}

func (c *Config) SetTarget(alias, url string) error {
	if c.Aliases == nil {
		c.Aliases = make(map[string]string)
	}
	if c.Targets == nil {
		c.Targets = make(map[string]interface{})
	}
	c.Aliases[alias] = url
	c.Current = alias
	if _, ok := c.Targets[url]; !ok {
		c.Targets[url] = nil
	}
	return nil
}

func (c *Config) SetToken(token string) error {
	if c.Current == "" {
		return fmt.Errorf("No target selected")
	}
	url, ok := c.Aliases[c.Current]
	if !ok {
		return fmt.Errorf("Unknown target '%s'", c.Current)
	}
	c.Targets[url] = token
	return nil
}

func (c *Config) URL() string {
	if url, ok := c.Aliases[c.Current]; ok {
		return url
	}
	return ""
}
