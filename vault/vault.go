package vault

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/starkandwayne/goutils/ansi"
	"github.com/starkandwayne/goutils/tree"
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

func shouldDebug() bool {
	d := strings.ToLower(os.Getenv("DEBUG"))
	return d != "" && d != "false" && d != "0" && d != "no" && d != "off"
}

func (v *Vault) request(req *http.Request) (*http.Response, error) {
	var (
		body []byte
		err  error
	)
	if req.Body != nil {
		body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Add("X-Vault-Token", v.Token)
	for i := 0; i < 10; i++ {
		if req.Body != nil {
			req.Body = ioutil.NopCloser(bytes.NewReader(body))
		}
		if shouldDebug() {
			r, _ := httputil.DumpRequest(req, true)
			fmt.Fprintf(os.Stderr, "Request:\n%s\n----------------\n", r)
		}
		res, err := v.Client.Do(req)
		if shouldDebug() {
			r, _ := httputil.DumpResponse(res, true)
			fmt.Fprintf(os.Stderr, "Response:\n%s\n----------------\n", r)
		}
		if err != nil {
			return nil, err
		}
		// Vault returns a 307 to redirect during HA / Auth
		switch res.StatusCode {
		case 307:
			// Note: this does not handle relative Location headers
			url, err := url.Parse(res.Header.Get("Location"))
			if err != nil {
				return nil, err
			}
			req.URL = url
			// ... and try again.

		default:
			return res, err
		}
	}

	return nil, fmt.Errorf("redirection loop detected")
}

func (v *Vault) Curl(method string, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, v.url("/v1/%s", path), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	return v.request(req)
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
		req, err = http.NewRequest("GET", v.url("/v1/%s", path), nil)
		if err != nil {
			return
		}
		res, err = v.request(req)
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

	var kid tree.Node
	for _, p := range l {
		var shouldAppend bool
		if p[len(p)-1:len(p)] == "/" {
			kid, err = v.Tree(path+"/"+p[0:len(p)-1], ansify)
			if len(kid.Sub) > 0 {
				shouldAppend = true
			}
			if ansify {
				name = ansi.Sprintf("@B{%s}", p)
			} else {
				name = p[0 : len(p)-1]
			}
		} else {
			shouldAppend = true
			if ansify {
				name = ansi.Sprintf("@G{%s}", p)
			} else {
				name = p
			}
			kid = tree.New(name)
		}
		if err != nil {
			return t, err
		}
		kid.Name = name
		if shouldAppend {
			t.Append(kid)
		}
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

func (v *Vault) DeleteTree(root string) error {
	tree, err := v.Tree(root, false)
	if err != nil {
		return err
	}
	for _, path := range tree.Paths("/") {
		err = v.Delete(path)
		if err != nil {
			return err
		}
	}
	return v.Delete(root)
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

func (v *Vault) MoveCopyTree(oldRoot, newRoot string, f func(string, string) error) error {
	tree, err := v.Tree(oldRoot, false)
	if err != nil {
		return err
	}
	for _, path := range tree.Paths("/") {
		newPath := strings.Replace(path, oldRoot, newRoot, 1)
		err = f(path, newPath)
		if err != nil {
			return err
		}
	}

	if _, err := v.Read(oldRoot); err != NotFound { // run through a copy unless we successfully got a 404 from this node
		return f(oldRoot, newRoot)
	}
	return nil
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

func (v *Vault) RetrievePem(path string) ([]byte, error) {
	res, err := v.Curl("GET", "/pki/"+path+"/pem", nil)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, DecodeErrorResponse(body)
	}

	return body, nil
}

func DecodeErrorResponse(body []byte) error {
	var raw map[string]interface{}

	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("Received non-200 with non-JSON payload:\n%s\n", body)
	}

	if rawErrors, ok := raw["errors"]; ok {
		var errors []string
		if elems, ok := rawErrors.([]interface{}); ok {
			for _, elem := range elems {
				if err, ok := elem.(string); ok {
					errors = append(errors, err)
				}
			}
			return fmt.Errorf(strings.Join(errors, "\n"))
		} else {
			return fmt.Errorf("Received unexpected format of Vault error messages:\n%v\n", errors)
		}
	} else {
		return fmt.Errorf("Received non-200 with no error messagess:\n%v\n", raw)
	}
}

type CertOptions struct {
	CN                string `json:"common_name"`
	TTL               string `json:"ttl,omitempty"`
	AltNames          string `json:"alt_names,omitempty"`
	IPSans            string `json:"ip_sans,omitempty"`
	ExcludeCNFromSans bool   `json:"exclude_cn_from_sans,omitempty"`
}

func (v *Vault) CreateSignedCertificate(role, path string, params CertOptions) error {
	parts := strings.Split(path, "/")
	cn := parts[len(parts)-1]
	params.CN = cn

	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	res, err := v.Curl("POST", fmt.Sprintf("pki/issue/%s", role), data)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		return fmt.Errorf("Unable to create certificate %s: %s\n", cn, DecodeErrorResponse(body))
	}

	var raw map[string]interface{}
	if err = json.Unmarshal(body, &raw); err == nil {
		if d, ok := raw["data"]; ok {
			if data, ok := d.(map[string]interface{}); ok {
				var cert, key, serial string
				var c, k, s interface{}
				var ok bool
				if c, ok = data["certificate"]; !ok {
					return fmt.Errorf("No certificate found when issuing certificate %s:\n%v\n", cn, data)
				}
				if cert, ok = c.(string); !ok {
					return fmt.Errorf("Invalid data type for certificate %s:\n%v\n", cn, data)
				}
				if k, ok = data["private_key"]; !ok {
					return fmt.Errorf("No private_key found when issuing certificate %s:\n%v\n", cn, data)
				}
				if key, ok = k.(string); !ok {
					return fmt.Errorf("Invalid data type for private_key %s:\n%v\n", cn, data)
				}
				if s, ok = data["serial_number"]; !ok {
					return fmt.Errorf("No serial_number found when issuing certificate %s:\n%v\n", cn, data)
				}
				if serial, ok = s.(string); !ok {
					return fmt.Errorf("Invalid data type for serial_number %s:\n%v\n", cn, data)
				}

				secret := NewSecret()
				secret.Set("cert", cert)
				secret.Set("key", key)
				secret.Set("serial", serial)
				return v.Write(path, secret)
			} else {
				fmt.Errorf("Invalid response datatype requesting certificate %s:\n%v\n", cn, d)
			}
		} else {
			fmt.Errorf("No data found when requesting certificate %s:\n%v\n", cn, d)
		}
	} else {
		return fmt.Errorf("Unparseable json creating certificate %s:\n%s\n", cn, body)
	}
	return nil
}

func (v *Vault) RevokeCertificate(serial string) error {
	if strings.ContainsRune(serial, '/') {
		secret, err := v.Read(serial)
		if err != nil {
			return err
		}
		if !secret.Has("serial") {
			return fmt.Errorf("Certificate specified using path %s, but no serial secret was found there", serial)
		}
		serial = secret.Get("serial")
	}

	d := struct {
		Serial string `json:"serial_number"`
	}{Serial: serial}

	data, err := json.Marshal(d)
	if err != nil {
		return err
	}

	res, err := v.Curl("POST", "pki/revoke", data)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("Unable to revoke certificate %s: %s\n", serial, DecodeErrorResponse(body))
	}
	return nil
}
