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
	SkipVerify map[string]bool `yaml:"skip_verify"`
}

func saferc() string {
	return fmt.Sprintf("%s/.saferc", os.Getenv("HOME"))
}

func svtoken() string {
	return fmt.Sprintf("%s/.svtoken", os.Getenv("HOME"))
}

func (c *Config) credentials() (string, string, bool, error) {
	if c.Current == "" {
		return "", "", false, nil
	}

	url, ok := c.Aliases[c.Current]
	if !ok {
		return "", "", false, fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	t, ok := c.Targets[url]
	if !ok {
		return "", "", false, fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	token := ""
	if t != nil {
		token = t.(string)
	}

	skipverify, ok := c.SkipVerify[url]
	if !ok {
		skipverify = false
	}

	return url, token, skipverify, nil
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

	url, token, skipverify, err := c.credentials()
	if err != nil {
		return err
	}

	b, err = yaml.Marshal(
		struct {
			URL   string `json:"vault"`
			Token string `json:"token"`
			SkipVerify bool `json:"skip_verify"`
		}{url, token, skipverify})
	if err != nil {
		return err
	}

	return ioutil.WriteFile(svtoken(), b, 0600)
}

func (c *Config) Apply() error {
	url, token, skipverify, err := c.credentials()
	if err != nil {
		return err
	}

	if url != "" {
		os.Setenv("VAULT_ADDR", url)
		os.Setenv("VAULT_TOKEN", token)
		if skipverify {
			os.Setenv("VAULT_SKIP_VERIFY", "1")
		}
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

func (c *Config) SetCurrent(alias string, reskip bool) error {
	if url, ok := c.Aliases[alias]; ok {
		c.Current = alias
		if reskip {
			c.SkipVerify[url] = true
		}
		return nil
	}
	return fmt.Errorf("Unknown target '%s'", alias)
}

func (c *Config) SetTarget(alias, url string, skipverify bool) error {
	if c.Aliases == nil {
		c.Aliases = make(map[string]string)
	}
	if c.Targets == nil {
		c.Targets = make(map[string]interface{})
	}
	if c.SkipVerify == nil {
		c.SkipVerify = make(map[string]bool)
	}
	c.Aliases[alias] = url
	c.Current = alias

	c.SkipVerify[url] = skipverify
	if _, ok := c.Targets[url]; !ok {
		c.Targets[url] = nil
		c.SkipVerify[url] = false
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

func (c *Config) Verified() bool {
	if url, ok := c.Aliases[c.Current]; ok {
		if skip, ok := c.SkipVerify[url]; ok && skip {
			return false
		}
		return true
	}
	return false
}
