package rc

import (
	"io/ioutil"
	"fmt"
	"os"

	"github.com/ghodss/yaml"
)

type Config struct {
	Current string `yaml:"current"`
	Targets map[string] interface{} `yaml:"targets"`
	Aliases map[string] string `yaml:"aliases"`
}

func Path() string {
	return fmt.Sprintf("%s/.saferc", os.Getenv("HOME"))
}

func Apply() Config {
	c, err := ReadConfig(Path())
	if err != nil {
		return c
	}

	c.Apply()
	return c
}

func ReadConfig(path string) (Config, error) {
	var c Config

	if path == "" {
		path = Path()
	}

	b, err := ioutil.ReadFile(path);
	if err != nil {
		return c, err
	}

	err = yaml.Unmarshal(b, &c)
	return c, err
}

func (c *Config) Write(path string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	if path == "" {
		path = Path()
	}

	err = ioutil.WriteFile(path, b, 0600)
	return err
}

func (c *Config) Apply() error {
	if c.Current == "" {
		return nil
	}

	url, ok := c.Aliases[c.Current]
	if !ok {
		return fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	t, ok := c.Targets[url]
	if !ok {
		return fmt.Errorf("Current target vault '%s' not found in ~/.saferc", c.Current)
	}

	token := ""
	if t != nil {
		token = t.(string)
	}

	os.Setenv("VAULT_ADDR", url)
	os.Setenv("VAULT_TOKEN", token)
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
		c.Aliases = make(map[string] string)
	}
	if c.Targets == nil {
		c.Targets = make(map[string] interface{})
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
