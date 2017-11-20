package rc

import (
	"io/ioutil"
	"os"
	"strings"

	fmt "github.com/jhunt/go-ansi"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Version int               `yaml:"version"`
	Current string            `yaml:"current"`
	Vaults  map[string]*Vault `yaml:"vaults"`
}

type Vault struct {
	URL        string `yaml:"url"`
	Token      string `yaml:"token"`
	SkipVerify bool   `yaml:"skip_verify"`
}

type oldConfig struct {
	Current    string                 `yaml:"Current"`
	Targets    map[string]interface{} `yaml:"Targets"`
	Aliases    map[string]string      `yaml:"Aliases"`
	SkipVerify map[string]bool        `yaml:"SkipVerify"`
}

func saferc() string {
	return fmt.Sprintf("%s/.saferc", os.Getenv("HOME"))
}

func svtoken() string {
	return fmt.Sprintf("%s/.svtoken", os.Getenv("HOME"))
}

func (legacy *oldConfig) convert() Config {
	c := Config{
		Version: 1,
		Current: legacy.Current,
		Vaults:  make(map[string]*Vault),
	}

	for alias, url := range legacy.Aliases {
		v := &Vault{
			URL: url,
		}
		if skip, ok := legacy.SkipVerify[url]; ok {
			v.SkipVerify = skip
		}
		if token, ok := legacy.Targets[url]; ok && token != nil {
			v.Token = token.(string)
		}
		c.Vaults[alias] = v
	}

	return c
}

func (c *Config) credentials() (string, string, bool, error) {
	if c.Current == "" {
		return "", "", false, nil
	}

	v, ok := c.Vaults[c.Current]
	if !ok {
		return "", "", false, fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	return v.URL, v.Token, v.SkipVerify, nil
}

func Apply() Config {
	var c Config

	b, err := ioutil.ReadFile(saferc())
	if err != nil {
		return Config{Version: 1}
	}

	if err = yaml.Unmarshal(b, &c); err != nil {
		return Config{Version: 1}
	}
	if c.Version == 0 {
		var legacy oldConfig
		if err = yaml.Unmarshal(b, &legacy); err != nil {
			return c
		}
		c = legacy.convert()
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
			URL        string `json:"vault"`
			Token      string `json:"token"`
			SkipVerify bool   `json:"skip_verify"`
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
	if v, ok := c.Vaults[alias]; ok {
		c.Current = alias
		if reskip {
			v.SkipVerify = true
		}
		return nil
	}
	return fmt.Errorf("Unknown target '%s'", alias)
}

func (c *Config) SetTarget(alias, url string, skipverify bool) error {
	if c.Vaults == nil {
		c.Vaults = make(map[string]*Vault)
	}

	c.Current = alias
	c.Vaults[alias] = &Vault{
		URL:        url,
		SkipVerify: skipverify,
	}

	return nil
}

func (c *Config) SetToken(token string) error {
	if c.Current == "" {
		return fmt.Errorf("No target selected")
	}
	v, ok := c.Vaults[c.Current]
	if !ok {
		return fmt.Errorf("Unknown target '%s'", c.Current)
	}
	v.Token = token
	return nil
}

func (c *Config) URL() string {
	if v, ok := c.Vaults[c.Current]; ok {
		return v.URL
	}
	return ""
}

func (c *Config) Verified() bool {
	if v, ok := c.Vaults[c.Current]; ok {
		return !v.SkipVerify
	}
	return false
}
