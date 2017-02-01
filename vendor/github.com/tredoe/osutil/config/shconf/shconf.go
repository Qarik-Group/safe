// Copyright 2012 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package shconf implements a parser and scanner for the configuration in
// format shell-variable.
//
// The configuration file consists on entries with the format:
//   "key" [separator] "value"
// The comments are indicated by "#" at the beginning of a line and upon the keys.
package shconf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"sync"

	"github.com/tredoe/osutil/file"
)

var (
	ErrKey       = errors.New("key not found")
	ErrStructPtr = errors.New("argument must be a pointer to struct")
)

// A TypeError represents the type no supported in function Unmarshal.
type TypeError string

func (e TypeError) Error() string { return "type no supported: " + string(e) }

// A Config represents the configuration.
type Config struct {
	sync.RWMutex

	data map[string]string // key: value

	separator []byte
	filename  string
}

// ParseFile creates a new Config and parses the file configuration from the
// named file.
func ParseFile(name string) (*Config, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		sync.RWMutex{},
		make(map[string]string),
		make([]byte, 0),
		file.Name(),
	}
	cfg.Lock()
	defer cfg.Unlock()
	defer file.Close()

	gotSeparator := false
	s := NewScanner(file)

	for found := s.Scan(); found; found = s.Scan() {
		if found {
			k, v := s.Text()
			cfg.data[k] = v

			if !gotSeparator {
				cfg.separator = s.Separator()
				gotSeparator = true
			}
			continue
		} else if s.Err() != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// Print outputs the keys and values parsed.
func (c *Config) Print() {
	fmt.Println(c.filename)
	for k, v := range c.data {
		fmt.Printf("\t%s: %s\n", k, v)
	}
}

// Separator returns the character/s used to separate the key from the value.
func (c *Config) Separator() []byte { return c.separator }

// Unmarshal assigns values into the pointer to struct given by out, for the
// keys found.
//
// The valid types in the struct fields for the matched keys are: bool, int,
// uint, float64, string.
//
// The errors that Unmarshal return can be ErrStructPtr or TypeError.
func (c *Config) Unmarshal(out interface{}) error {
	valueof := reflect.ValueOf(out)
	if valueof.Kind() != reflect.Ptr {
		return ErrStructPtr
	}
	valueof = valueof.Elem()
	if valueof.Kind() != reflect.Struct {
		return ErrStructPtr
	}

	typeof := valueof.Type()

	for i := 0; i < valueof.NumField(); i++ {
		fieldT := typeof.Field(i)
		fieldV := valueof.Field(i)

		if value, found := c.data[fieldT.Name]; found {
			switch fieldV.Kind() {
			case reflect.Bool:
				v, _ := strconv.ParseBool(value)
				fieldV.SetBool(v)

			case reflect.Int:
				v, _ := strconv.ParseInt(value, 10, 0)
				fieldV.SetInt(v)
			case reflect.Uint:
				v, _ := strconv.ParseUint(value, 10, 0)
				fieldV.SetUint(v)

			case reflect.Float64:
				v, _ := strconv.ParseFloat(value, 64)
				fieldV.SetFloat(v)
			/*case reflect.Float32:
				v, _ := strconv.ParseFloat(value, 32)
				fieldV.SetFloat(v)*/

			case reflect.String:
				fieldV.SetString(value)

			default:
				return TypeError(fieldV.Kind().String())
			}
		}
	}
	return nil
}

// * * *

// Get returns the string value for a given key.
func (c *Config) Get(key string) (string, error) {
	if value, found := c.data[key]; found {
		return value, nil
	}
	return "", ErrKey
}

// Getbool returns the boolean value for a given key.
func (c *Config) Getbool(key string) (bool, error) {
	if value, found := c.data[key]; found {
		return strconv.ParseBool(value)
	}
	return false, ErrKey
}

// Getint returns the integer value for a given key.
func (c *Config) Getint(key string) (int, error) {
	if value, found := c.data[key]; found {
		v, err := strconv.ParseInt(value, 10, 0)
		return int(v), err
	}
	return 0, ErrKey
}

// Getuint returns the unsigned integer value for a given key.
func (c *Config) Getuint(key string) (uint, error) {
	if value, found := c.data[key]; found {
		v, err := strconv.ParseUint(value, 10, 0)
		return uint(v), err
	}
	return 0, ErrKey
}

// Getfloat returns the float value for a given key.
func (c *Config) Getfloat(key string) (float64, error) {
	if value, found := c.data[key]; found {
		return strconv.ParseFloat(value, 64)
	}
	return 0, ErrKey
}

// Set writes a new value for key.
func (c *Config) Set(key, value string) error {
	c.Lock()
	defer c.Unlock()

	if _, found := c.data[key]; !found {
		return ErrKey
	}

	separator := string(c.Separator())
	replAt := []file.ReplacerAtLine{
		{key + separator, separator + ".*", separator + value},
	}

	if err := file.ReplaceAtLine(c.filename, replAt); err != nil {
		return err
	}
	c.data[key] = value
	return nil
}
