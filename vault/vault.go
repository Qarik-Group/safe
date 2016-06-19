package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/jhunt/ansi"
	"github.com/jhunt/tree"
)

// A Vault represents a means for interacting with a remote Vault
// instance (unsealed and pre-authenticated) to read and write secrets.
type Vault struct {
	URL    string
	Token  string
	Client *http.Client
}

// NewVault creates a new Vault object.  If an empty token is specified,
// the current user's token is read from ~/.vault-token.
func NewVault(url, token string) (*Vault, error) {
	if token == "" {
		b, err := ioutil.ReadFile(fmt.Sprintf("%s/.vault-token", os.Getenv("HOME")))
		if err != nil {
			return nil, err
		}
		token = string(b)
	}

	if token == "" {
		return nil, fmt.Errorf("no vault token specified; are you authenticated?")
	}

	return &Vault{
		URL:   url,
		Token: token,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: os.Getenv("VAULT_SKIP_VERIFY") != "",
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				req.Header.Add("X-Vault-Token", token)
				return nil
			},
		},
	}, nil
}

func (v *Vault) url(f string, args ...interface{}) string {
	return v.URL + fmt.Sprintf(f, args...)
}

func (v *Vault) request(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Vault-Token", v.Token)
	return v.Client.Do(req)
}

// Read checks the Vault for a Secret at the specified path, and returns it.
// If there is nothing at that path, a nil *Secret will be returned, with no
// error.
func (v *Vault) Read(path string) (secret *Secret, err error) {
	secret = NewSecret()
	req, err := http.NewRequest("GET", v.url("/v1/%s", path), nil)
	if err != nil {
		return
	}
	res, err := v.request(req)
	if err != nil {
		return
	}

	switch res.StatusCode {
	case 200:
		break
	case 404:
		err = NotFound
		return
	default:
		err = fmt.Errorf("API %s", res.Status)
		return
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	var raw map[string]interface{}
	if err = json.Unmarshal(b, &raw); err != nil {
		return
	}

	if rawdata, ok := raw["data"]; ok {
		if data, ok := rawdata.(map[string]interface{}); ok {
			for k, v := range data {
				if s, ok := v.(string); ok {
					secret.data[k] = s
				} else {
					b, err = json.Marshal(v)
					if err != nil {
						return
					}
					secret.data[k] = string(b)
				}
			}

			return
		}
	}
	err = fmt.Errorf("malformed response from vault")
	return
}

// List returns the set of (relative) paths that are directly underneath
// the given path.  Intermediate path nodes are suffixed with a single "/",
// whereas leaf nodes (the secrets themselves) are not.
func (v *Vault) List(path string) (paths []string, err error) {
	req, err := http.NewRequest("GET", v.url("/v1/%s?list=1", path), nil)
	if err != nil {
		return
	}
	res, err := v.request(req)
	if err != nil {
		return
	}

	switch res.StatusCode {
	case 200:
		break
	case 404:
		err = NotFound
		return
	default:
		err = fmt.Errorf("API %s", res.Status)
		return
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	var r struct{ Data struct{ Keys []string } }
	if err = json.Unmarshal(b, &r); err != nil {
		return
	}
	return r.Data.Keys, nil
}

type Node struct {
	Path     string
	Children []Node
}

// Tree returns a tree that represents the hierarhcy of paths contained
// below the given path, inside of the Vault.
func (v *Vault) Tree(path string, ansify bool) (tree.Node, error) {
	name := path
	if ansify {
		name = ansi.Sprintf("@C{%s}", path)
	}
	t := tree.New(name)

	l, err := v.List(path)
	if err != nil {
		return t, err
	}

	seen := make(map[string]bool)
	var kid tree.Node
	for _, p := range l {
		if p[len(p)-1:len(p)] == "/" {
			if _, ok := seen[p[0:len(p)-1]]; ok {
				continue
			}
			kid, err = v.Tree(path+"/"+p[0:len(p)-1], ansify)
			if ansify {
				name = ansi.Sprintf("@B{%s}", p)
			} else {
				name = p[0 : len(p)-1]
			}
		} else {
			seen[p] = true
			kid, err = v.Tree(path+"/"+p, ansify)
			if ansify {
				name = ansi.Sprintf("@G{%s}", p)
			} else {
				name = p
			}
		}
		if err != nil {
			return t, err
		}
		kid.Name = name
		t.Append(kid)
	}
	return t, nil
}

// Write takes a Secret and writes it to the Vault at the specified path.
func (v *Vault) Write(path string, s *Secret) error {
	raw := s.JSON()
	if raw == "" {
		return fmt.Errorf("nothing to write")
	}

	req, err := http.NewRequest("POST", v.url("/v1/%s", path), strings.NewReader(raw))
	if err != nil {
		return err
	}
	res, err := v.request(req)
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case 200:
		break
	case 204:
		break
	default:
		return fmt.Errorf("API %s", res.Status)
	}

	return nil
}

// Delete removes the secret stored at the specified path.
func (v *Vault) Delete(path string) error {
	req, err := http.NewRequest("DELETE", v.url("/v1/%s", path), nil)
	if err != nil {
		return err
	}
	res, err := v.request(req)
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case 200:
		break
	case 204:
		break
	default:
		return fmt.Errorf("API %s", res.Status)
	}

	return nil
}

// Copy copies secrets from one path to another.
func (v *Vault) Copy(oldpath, newpath string) error {
	secret, err := v.Read(oldpath)
	if err != nil {
		return err
	}
	return v.Write(newpath, secret)
}

// Move moves secrets from one path to another.
func (v *Vault) Move(oldpath, newpath string) error {
	err := v.Copy(oldpath, newpath)
	if err != nil {
		return err
	}
	err = v.Delete(oldpath)
	if err != nil {
		return err
	}
	return nil
}
