package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/jhunt/go-ansi"
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
func NewVault(url, token string, auth bool) (*Vault, error) {
	if auth {
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
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve system root certificate authorities: %s", err)
	}

	return &Vault{
		URL:   strings.TrimSuffix(url, "/"),
		Token: token,
		Client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					RootCAs:            roots,
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
	path = Canonicalize(path)
	req, err := http.NewRequest(method, v.url("/v1/%s", path), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	return v.request(req)
}

func (v *Vault) Configure(path string, params map[string]string) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}

	res, err := v.Curl("POST", path, data)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 && res.StatusCode != 204 {
		return fmt.Errorf("configuration via '%s' failed", path)
	}

	return nil
}

// Read checks the Vault for a Secret at the specified path, and returns it.
// If there is nothing at that path, a nil *Secret will be returned, with no
// error.
func (v *Vault) Read(path string) (secret *Secret, err error) {
	//split at last colon, if present
	path, key := ParsePath(path)

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
		err = NewSecretNotFoundError(path)
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
				if (key != "" && k == key) || key == "" {
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
			}

			if key != "" && len(secret.data) == 0 {
				err = NewKeyNotFoundError(path, key)
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
	path = Canonicalize(path)

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
			err = NewSecretNotFoundError(path)
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

type TreeOptions struct {
	UseANSI      bool /* Use ANSI colorizing sequences */
	HideLeaves   bool /* Hide leaf nodes of the tree (actual secrets) */
	ShowKeys     bool /* Include keys in the output */
	InSubbranch  bool /* If true, suppresses key output on branches */
	StripSlashes bool /* If true, strip the trailing slashes from interior nodes */
}

func (v *Vault) walktree(path string, options TreeOptions) (tree.Node, int, error) {
	t := tree.New(path)
	l, err := v.List(path)
	if err != nil {
		return t, 0, err
	}

	var key_fmt string
	if options.UseANSI {
		key_fmt = "@Y{:%s}"
	} else {
		key_fmt = ":%s"
	}
	if options.ShowKeys && !options.InSubbranch {
		if s, err := v.Read(path); err == nil {
			for _, key := range s.Keys() {
				key_name := ansi.Sprintf(key_fmt, key)
				t.Append(tree.New(key_name))
			}
		}
	}
	options.InSubbranch = true
	for _, p := range l {
		if strings.HasSuffix(p, "/") {
			kid, n, err := v.walktree(path+"/"+p[0:len(p)-1], options)
			if err != nil {
				return t, 0, err
			}
			if n == 0 {
				fmt.Fprintf(os.Stderr, "%s\n", kid.Name)
				continue
			}
			if options.StripSlashes {
				p = p[0 : len(p)-1]
			}
			if options.UseANSI {
				kid.Name = ansi.Sprintf("@B{%s}", p)
			} else {
				kid.Name = p
			}
			t.Append(kid)

		} else if options.HideLeaves {
			continue

		} else {
			var name string
			if options.UseANSI {
				name = ansi.Sprintf("@G{%s}", p)
			} else {
				name = p
			}
			leaf := tree.New(name)
			if options.ShowKeys {
				if s, err := v.Read(path + "/" + p); err == nil {
					for _, key := range s.Keys() {
						key_name := ansi.Sprintf(key_fmt, key)
						leaf.Append(tree.New(key_name))
					}
				} else {
					fmt.Fprintf(os.Stderr, "error: %s\n", err)
				}

			}
			t.Append(leaf)
		}
	}
	return t, len(l), nil
}

// Tree returns a tree that represents the hierarchy of paths contained
// below the given path, inside of the Vault.
func (v *Vault) Tree(path string, options TreeOptions) (tree.Node, error) {
	path = Canonicalize(path)

	t, _, err := v.walktree(path, options)
	if err != nil {
		return t, err
	}
	if options.UseANSI {
		t.Name = ansi.Sprintf("@C{%s}", path)
	} else {
		t.Name = path
	}
	return t, nil
}

// Write takes a Secret and writes it to the Vault at the specified path.
func (v *Vault) Write(path string, s *Secret) error {
	path = Canonicalize(path)
	if strings.Contains(path, ":") {
		return fmt.Errorf("cannot write to paths in /path:key notation")
	}

	//If our secret has become empty (through key deletion, most likely)
	// make sure to clean up the secret
	if s.Empty() {
		return v.deleteIfPresent(path)
	}

	raw := s.JSON()

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

//errIfFolder returns an error with your provided message if the given path exists,
// either as a secret or a folder.
// Can also throw an error if contacting the backend failed, in which case that error
// is returned.
func (v *Vault) errIfFolder(path, message string, args ...interface{}) error {
	path = Canonicalize(path)

	//need to check if length of list is 0 because prior to vault 0.6.0, no 404 is
	//given for attempting to list a path which does not exist.
	if paths, err := v.List(path); err == nil && len(paths) != 0 { //...see if it is a subtree "folder"
		// the "== nil" is not a typo. if there is an error, NotFound or otherwise,
		// simply fall through to the error return below
		// Otherwise, give a different error signifying that the problem is that
		// the target is a directory when we expected a secret.
		return fmt.Errorf(message, args...)
	} else if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

func (v *Vault) verifySecretExists(path string) error {
	path = Canonicalize(path)

	_, err := v.Read(path)
	if err != nil && IsNotFound(err) { //if this was not a leaf node (secret)...
		if folderErr := v.errIfFolder(path, "`%s` points to a folder, not a secret", path); folderErr != nil {
			return folderErr
		}
	}
	return err
}

//DeleteTree recursively deletes the leaf nodes beneath the given root until
// the root has no children, and then deletes that.
func (v *Vault) DeleteTree(root string) error {
	root = Canonicalize(root)

	tree, err := v.Tree(root, TreeOptions{
		StripSlashes: true,
	})
	if err != nil {
		return err
	}
	for _, path := range tree.Paths("/") {
		err = v.deleteEntireSecret(path)
		if err != nil {
			return err
		}
	}
	return v.deleteEntireSecret(root)
}

// Delete removes the secret or key stored at the specified path.
func (v *Vault) Delete(path string) error {
	path = Canonicalize(path)

	if err := v.verifySecretExists(path); err != nil {
		return err
	}

	secret, key := ParsePath(path)
	if key == "" {
		return v.deleteEntireSecret(path)
	}
	return v.deleteSpecificKey(secret, key)
}

func (v *Vault) deleteEntireSecret(path string) error {

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

func (v *Vault) deleteSpecificKey(path, key string) error {
	secret, err := v.Read(path)
	if err != nil {
		return err
	}
	deleted := secret.Delete(key)
	if !deleted {
		return NewKeyNotFoundError(path, key)
	}
	err = v.Write(path, secret)
	return err
}

//deleteIfPresent first checks to see if there is a Secret at the given path,
// and if so, it deletes it. Otherwise, no error is thrown
func (v *Vault) deleteIfPresent(path string) error {
	secretpath, _ := ParsePath(path)
	if _, err := v.Read(secretpath); err != nil {
		if IsSecretNotFound(err) {
			return nil
		}
		return err
	}

	err := v.Delete(path)
	if IsKeyNotFound(err) {
		return nil
	}
	return err
}

// Copy copies secrets from one path to another.
// With a secret:key specified: key -> key is good.
// key -> no-key is okay - we assume to keep old key name
// no-key -> key is bad. That makes no sense and the user should feel bad.
// Returns KeyNotFoundError if there is no such specified key in the secret at oldpath
func (v *Vault) Copy(oldpath, newpath string, skipIfExists bool, quiet bool) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	if err := v.verifySecretExists(oldpath); err != nil {
		return err
	}
	if skipIfExists {
		if _, err := v.Read(newpath); err == nil {
			if !quiet {
				ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as that would clobber existing data}\n", newpath)
			}
			return nil
		} else if !IsNotFound(err) {
			return err
		}
	}

	srcPath, _ := ParsePath(oldpath)
	srcSecret, err := v.Read(srcPath)
	if err != nil {
		return err
	}

	var copyFn func(string, string, *Secret, bool) error
	if PathHasKey(oldpath) {
		copyFn = v.copyKey
	} else {
		copyFn = v.copyEntireSecret
	}

	return copyFn(oldpath, newpath, srcSecret, skipIfExists)
}

func (v *Vault) copyEntireSecret(oldpath, newpath string, src *Secret, skipIfExists bool) (err error) {
	if PathHasKey(newpath) {
		return fmt.Errorf("Cannot move full secret `%s` into specific key `%s`", oldpath, newpath)
	}
	if skipIfExists {
		if _, err := v.Read(newpath); err == nil {
			return ansi.Errorf("@R{BUG: Tried to replace} @C{%s} @R{with} @C{%s}@R{, but it already exists}", oldpath, newpath)
		} else if !IsNotFound(err) {
			return err
		}
	}
	return v.Write(newpath, src)
}

func (v *Vault) copyKey(oldpath, newpath string, src *Secret, skipIfExists bool) (err error) {
	_, srcKey := ParsePath(oldpath)
	if !src.Has(srcKey) {
		return NewKeyNotFoundError(oldpath, srcKey)
	}

	dstPath, dstKey := ParsePath(newpath)
	//If destination has no key, then assume to give it the same key as the src
	if dstKey == "" {
		dstKey = srcKey
	}
	dst, err := v.Read(dstPath)
	if err != nil {
		if !IsSecretNotFound(err) {
			return err
		}
		dst = NewSecret() //If no secret is already at the dst, initialize a new one
	}
	err = dst.Set(dstKey, src.Get(srcKey), skipIfExists)
	if err != nil {
		return err
	}
	return v.Write(dstPath, dst)
}

//MoveCopyTree will recursively copy all nodes from the root to the new location.
// This function will get confused about 'secret:key' syntax, so don't let those
// get routed here - they don't make sense for a recursion anyway.
func (v *Vault) MoveCopyTree(oldRoot, newRoot string, f func(string, string, bool, bool) error, skipIfExists bool, quiet bool) error {
	oldRoot = Canonicalize(oldRoot)
	newRoot = Canonicalize(newRoot)

	tree, err := v.Tree(oldRoot, TreeOptions{})
	if err != nil {
		return err
	}
	if skipIfExists {
		newTree, err := v.Tree(newRoot, TreeOptions{})
		if err != nil && !IsNotFound(err) {
			return err
		}
		existing := map[string]bool{}
		for _, path := range newTree.Paths("/") {
			existing[path] = true
		}
		existingPaths := []string{}
		for _, path := range tree.Paths("/") {
			newPath := strings.Replace(path, oldRoot, newRoot, 1)
			if existing[newPath] {
				existingPaths = append(existingPaths, newPath)
			}
		}
		if len(existingPaths) > 0 {
			if !quiet {
				ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as the following paths would be clobbered:}\n", newRoot)
				for _, path := range existingPaths {
					ansi.Fprintf(os.Stderr, "@R{- }@C{%s}\n", path)
				}
			}
			return nil
		}
	}
	for _, path := range tree.Paths("/") {
		newPath := strings.Replace(path, oldRoot, newRoot, 1)
		err = f(path, newPath, skipIfExists, quiet)
		if err != nil {
			return err
		}
	}

	if _, err := v.Read(oldRoot); !IsNotFound(err) { // run through a copy unless we successfully got a 404 from this node
		return f(oldRoot, newRoot, skipIfExists, quiet)
	}
	return nil
}

// Move moves secrets from one path to another.
// A move is semantically a copy and then a deletion of the original item. For
// more information on the behavior of Move pertaining to keys, look at Copy.
func (v *Vault) Move(oldpath, newpath string, skipIfExists bool, quiet bool) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	if err := v.verifySecretExists(oldpath); err != nil {
		return err
	}

	err := v.Copy(oldpath, newpath, skipIfExists, quiet)
	if err != nil {
		return err
	}
	err = v.Delete(oldpath)
	if err != nil {
		return err
	}
	return nil
}

type mountpoint struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Config      map[string]interface{} `json:"config"`
}

func convertMountpoint(o interface{}) (mountpoint, bool) {
	mount := mountpoint{}
	if m, ok := o.(map[string]interface{}); ok {
		if t, ok := m["type"].(string); ok {
			mount.Type = t
		} else {
			return mount, false
		}
		if d, ok := m["description"].(string); ok {
			mount.Description = d
		} else {
			return mount, false
		}
		if c, ok := m["config"].(map[string]interface{}); ok {
			mount.Config = c
		} else {
			return mount, false
		}
		return mount, true
	}
	return mount, false
}

func (v *Vault) Mounts(typ string) ([]string, error) {
	res, err := v.Curl("GET", "sys/mounts", nil)
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

	mm := make(map[string]interface{})
	if err := json.Unmarshal(body, &mm); err != nil {
		return nil, fmt.Errorf("Received invalid JSON '%s' from Vault: %s\n",
			body, err)
	}

	l := make([]string, 0)
	for k, m := range mm {
		if mount, ok := convertMountpoint(m); ok {
			if typ == "" || mount.Type == typ {
				l = append(l, strings.TrimSuffix(k, "/")+"/")
			}
		}
	}
	return l, nil
}

func (v *Vault) IsMounted(typ, path string) (bool, error) {
	mounts, err := v.Mounts(typ)
	if err != nil {
		return false, err
	}

	for _, at := range mounts {
		if at == path || at == path+"/" {
			return true, nil
		}
	}
	return false, nil
}

func (v *Vault) Mount(typ, path string, params map[string]interface{}) error {
	mounted, err := v.IsMounted(typ, path)
	if err != nil {
		return err
	}

	if !mounted {
		p := mountpoint{
			Type:        typ,
			Description: "(managed by safe)",
			Config:      params,
		}
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}

		res, err := v.Curl("POST", fmt.Sprintf("sys/mounts/%s", path), data)
		if err != nil {
			return err
		}

		if res.StatusCode != 204 {
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return err
			}
			return DecodeErrorResponse(body)
		}

	} else {
		data, err := json.Marshal(params)
		if err != nil {
			return err
		}

		res, err := v.Curl("POST", fmt.Sprintf("sys/mounts/%s/tune", path), data)
		if err != nil {
			return err
		}

		if res.StatusCode != 204 {
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return err
			}
			return DecodeErrorResponse(body)
		}
	}

	return nil
}

func (v *Vault) RetrievePem(backend, path string) ([]byte, error) {
	if err := v.CheckPKIBackend(backend); err != nil {
		return nil, err
	}

	res, err := v.Curl("GET", fmt.Sprintf("/%s/%s/pem", backend, path), nil)
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

func (v *Vault) CreateSignedCertificate(backend, role, path string, params CertOptions, skipIfExists bool) error {
	if err := v.CheckPKIBackend(backend); err != nil {
		return err
	}

	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	res, err := v.Curl("POST", fmt.Sprintf("%s/issue/%s", backend, role), data)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		return fmt.Errorf("Unable to create certificate %s: %s\n", params.CN, DecodeErrorResponse(body))
	}

	var raw map[string]interface{}
	if err = json.Unmarshal(body, &raw); err == nil {
		if d, ok := raw["data"]; ok {
			if data, ok := d.(map[string]interface{}); ok {
				var cert, key, serial string
				var c, k, s interface{}
				var ok bool
				if c, ok = data["certificate"]; !ok {
					return fmt.Errorf("No certificate found when issuing certificate %s:\n%v\n", params.CN, data)
				}
				if cert, ok = c.(string); !ok {
					return fmt.Errorf("Invalid data type for certificate %s:\n%v\n", params.CN, data)
				}
				if k, ok = data["private_key"]; !ok {
					return fmt.Errorf("No private_key found when issuing certificate %s:\n%v\n", params.CN, data)
				}
				if key, ok = k.(string); !ok {
					return fmt.Errorf("Invalid data type for private_key %s:\n%v\n", params.CN, data)
				}
				if s, ok = data["serial_number"]; !ok {
					return fmt.Errorf("No serial_number found when issuing certificate %s:\n%v\n", params.CN, data)
				}
				if serial, ok = s.(string); !ok {
					return fmt.Errorf("Invalid data type for serial_number %s:\n%v\n", params.CN, data)
				}

				secret, err := v.Read(path)
				if err != nil && !IsNotFound(err) {
					return err
				}
				err = secret.Set("cert", cert, skipIfExists)
				if err != nil {
					return err
				}
				err = secret.Set("key", key, skipIfExists)
				if err != nil {
					return err
				}
				err = secret.Set("combined", cert+key, skipIfExists)
				if err != nil {
					return err
				}
				err = secret.Set("serial", serial, skipIfExists)
				if err != nil {
					return err
				}
				return v.Write(path, secret)
			} else {
				return fmt.Errorf("Invalid response datatype requesting certificate %s:\n%v\n", params.CN, d)
			}
		} else {
			return fmt.Errorf("No data found when requesting certificate %s:\n%v\n", params.CN, d)
		}
	} else {
		return fmt.Errorf("Unparseable json creating certificate %s:\n%s\n", params.CN, body)
	}
}

func (v *Vault) RevokeCertificate(backend, serial string) error {
	if err := v.CheckPKIBackend(backend); err != nil {
		return err
	}

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

	res, err := v.Curl("POST", fmt.Sprintf("%s/revoke", backend), data)
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

func (v *Vault) CheckPKIBackend(backend string) error {
	if mounted, _ := v.IsMounted("pki", backend); !mounted {
		return fmt.Errorf("The PKI backend `%s` has not been configured. Try running `safe pki init --backend %s`\n", backend, backend)
	}
	return nil
}
