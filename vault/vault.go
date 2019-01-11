package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
)

type Vault struct {
	client *vaultkv.KV
}

// NewVault creates a new Vault object.  If an empty token is specified,
// the current user's token is read from ~/.vault-token.
func NewVault(u, token string, auth bool) (*Vault, error) {
	if auth {
		if token == "" {
			b, err := ioutil.ReadFile(fmt.Sprintf("%s/.vault-token", userHomeDir()))
			if err != nil {
				return nil, err
			}
			token = string(b)
		}

		if token == "" {
			return nil, fmt.Errorf("no vault token specified; are you authenticated?")
		}
	}

	// x509.SystemCertPool is not implemented for windows currently.
	// If nil is supplied for RootCAs, the system will verify the certs as per
	// https://golang.org/src/crypto/x509/verify.go (Line 741)
	roots, err := x509.SystemCertPool()
	if err != nil && runtime.GOOS != "windows" {
		return nil, fmt.Errorf("unable to retrieve system root certificate authorities: %s", err)
	}

	vaultURL, err := url.Parse(strings.TrimSuffix(u, "/"))
	if err != nil {
		return nil, fmt.Errorf("Could not parse Vault URL: %s", err)
	}

	//The default port for Vault is typically 8200 (which is the VaultKV default),
	// but safe has historically ignored that and used the default http or https
	// port, depending on which was specified as the scheme
	if vaultURL.Port() == "" {
		port := ":80"
		if strings.ToLower(vaultURL.Scheme) == "https" {
			port = ":443"
		}
		vaultURL.Host = vaultURL.Host + port
	}

	return &Vault{
		client: (&vaultkv.Client{
			VaultURL:  vaultURL,
			AuthToken: token,
			Client: &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					TLSClientConfig: &tls.Config{
						RootCAs:            roots,
						InsecureSkipVerify: os.Getenv("VAULT_SKIP_VERIFY") != "",
					},
				},
			},
			Trace: func() (ret io.Writer) {
				if shouldDebug() {
					ret = os.Stderr
				}
				return ret
			}(),
		}).NewKV(),
	}, nil
}

func (v *Vault) Client() *vaultkv.KV {
	return v.client
}

func (v *Vault) MountVersion(path string) (uint, error) {
	path = Canonicalize(path)
	return v.client.MountVersion(path)
}

func (v *Vault) Versions(path string) ([]vaultkv.KVVersion, error) {
	path = Canonicalize(path)
	ret, err := v.client.Versions(path)
	if vaultkv.IsNotFound(err) {
		return nil, NewSecretNotFoundError(path)
	}

	return ret, err
}

func shouldDebug() bool {
	d := strings.ToLower(os.Getenv("DEBUG"))
	return d != "" && d != "false" && d != "0" && d != "no" && d != "off"
}

func (v *Vault) Curl(method string, path string, body []byte) (*http.Response, error) {
	path = Canonicalize(path)
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("Could not parse input path: %s", err.Error())
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		panic("Could not parse query: " + err.Error())
	}

	return v.client.Client.Curl(method, u.Path, query, bytes.NewBuffer(body))
}

// Read checks the Vault for a Secret at the specified path, and returns it.
// If there is nothing at that path, a nil *Secret will be returned, with no
// error.
func (v *Vault) Read(path string) (secret *Secret, err error) {
	path = Canonicalize(path)
	path, key, version := ParsePath(path)

	secret = NewSecret()

	raw := map[string]interface{}{}
	_, err = v.client.Get(path, &raw, &vaultkv.KVGetOpts{Version: uint(version)})
	if err != nil {
		if vaultkv.IsNotFound(err) {
			err = NewSecretNotFoundError(path)
		}
		return
	}

	if key != "" {
		val, found := raw[key]
		if !found {
			return nil, NewKeyNotFoundError(path, key)
		}
		raw = map[string]interface{}{key: val}
	}

	for k, v := range raw {
		if (key != "" && k == key) || key == "" {
			if s, ok := v.(string); ok {
				secret.data[k] = s
			} else {
				var b []byte
				b, err = json.Marshal(v)
				if err != nil {
					return
				}
				secret.data[k] = string(b)
			}
		}
	}

	return
}

// List returns the set of (relative) paths that are directly underneath
// the given path.  Intermediate path nodes are suffixed with a single "/",
// whereas leaf nodes (the secrets themselves) are not.
func (v *Vault) List(path string) (paths []string, err error) {
	path = Canonicalize(path)

	paths, err = v.client.List(path)
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}

	return paths, err
}

// Write takes a Secret and writes it to the Vault at the specified path.
func (v *Vault) Write(path string, s *Secret) error {
	path = Canonicalize(path)
	if strings.Contains(path, ":") {
		return fmt.Errorf("cannot write to paths in /path:key notation")
	}

	if s.Empty() {
		return v.deleteIfPresent(path, DeleteOpts{})
	}

	_, err := v.client.Set(path, s.data, nil)
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}

	return err
}

//errIfFolder returns an error with your provided message if the given path is a folder.
// Can also throw an error if contacting the backend failed, in which case that error
// is returned.
func (v *Vault) errIfFolder(path, message string, args ...interface{}) error {
	path = Canonicalize(path)
	if _, err := v.List(path); err == nil {
		//We don't want the folder error to be ignored because of the -f flag to rm,
		// so we explicitly don't make this a secretNotFound error
		return fmt.Errorf(message, args...)
	} else if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

const (
	verifyStateAlive uint = iota
	verifyStateAliveOrDeleted
)

type verifyOpts struct {
	AnyVersion bool
	State      uint
}

func (v *Vault) verifySecretState(path string, opts verifyOpts) error {
	secret, _, version := ParsePath(path)
	mountV, err := v.MountVersion(secret)
	if err != nil {
		return err
	}

	var deletedErr = secretNotFound{fmt.Sprintf("`%s' is deleted", path)}
	var destroyedErr = secretNotFound{fmt.Sprintf("`%s' is destroyed", path)}

	switch mountV {
	case 1:
		return v.verifySecretExists(path)
	case 2:
		versions, err := v.Versions(secret)
		if err != nil {
			if IsNotFound(err) {
				err = v.errIfFolder(path, "`%s' points to a folder, not a secret", path)
				if err != nil {
					return err
				}

				return NewSecretNotFoundError(secret)
			}

			return err
		}

		if !opts.AnyVersion {
			var v vaultkv.KVVersion
			if version == 0 {
				v = versions[len(versions)-1]
			} else {
				if uint64(versions[0].Version) > version {
					return destroyedErr
				}

				if version > uint64(versions[len(versions)-1].Version) {
					return secretNotFound{fmt.Sprintf("`%s' references a version that does not yet exist", path)}
				}

				idx := version - uint64(versions[0].Version)
				v = versions[idx]
			}

			if v.Destroyed {
				return destroyedErr
			}
			if opts.State == verifyStateAlive && v.Deleted {
				return deletedErr
			}
		} else {
			for i := range versions {
				if !(versions[i].Deleted || versions[i].Destroyed) || (opts.State == verifyStateAliveOrDeleted && !versions[i].Destroyed) {
					return nil
				}
			}

			//If we got this far, we couldn't find a version that satisfied our constraints
			if opts.State == verifyStateAlive {
				return secretNotFound{fmt.Sprintf("No living versions for `%s'", path)}
			} else {
				return secretNotFound{fmt.Sprintf("No living or deleted versions for `%s'", path)}
			}
		}

	default:
		return fmt.Errorf("Unsupported mount version: %d", mountV)
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

func (v *Vault) verifySecretUndestroyed(path string) error {
	path = Canonicalize(path)
	secret, _, version := ParsePath(path)
	allVersions, err := v.Client().Versions(secret)
	if err != nil {
		return err
	}

	destroyedErr := fmt.Errorf("`%s' is destroyed", path)

	if version == 0 {
		if allVersions[len(allVersions)-1].Destroyed {
			return destroyedErr
		}

		return nil
	}

	firstVersion := allVersions[0].Version
	if uint(version) < firstVersion {
		return destroyedErr
	}

	idx := int(uint(version) - firstVersion)
	if idx >= len(allVersions) {
		return fmt.Errorf("version %d of `%s' does not yet exist", version, secret)
	}

	if allVersions[idx].Destroyed {
		return destroyedErr
	}

	return nil
}

//DeleteTree recursively deletes the leaf nodes beneath the given root until
//the root has no children, and then deletes that.
func (v *Vault) DeleteTree(root string, opts DeleteOpts) error {
	root = Canonicalize(root)

	secrets, err := v.ConstructSecrets(root, TreeOpts{FetchKeys: false, SkipVersionInfo: true, AllowDeletedSecrets: true})
	if err != nil {
		return err
	}
	for _, path := range secrets.Paths() {
		err = v.deleteEntireSecret(path, opts.Destroy, opts.All)
		if err != nil {
			return err
		}
	}

	mount, err := v.Client().MountPath(root)
	if err != nil {
		return err
	}

	if strings.Trim(root, "/") != strings.Trim(mount, "/") {
		err = v.deleteEntireSecret(root, opts.Destroy, opts.All)
	}

	return err
}

type DeleteOpts struct {
	Destroy bool
	All     bool
}

func (v *Vault) canSemanticallyDelete(path string) error {
	justSecret, key, version := ParsePath(path)
	if key == "" || version == 0 {
		return nil
	}

	versions, err := v.Versions(justSecret)
	if err != nil {
		return err
	}

	if versions[len(versions)-1].Version == uint(version) {
		return nil
	}

	s, err := v.Read(path)
	if err != nil {
		return err
	}

	if len(s.data) != 1 || !s.Has(key) {
		return fmt.Errorf("Cannot delete specific non-isolated key of non-latest version")
	}

	return nil
}

// Delete removes the secret or key stored at the specified path.
// If destroy is true and the mount is v2, the latest version is destroyed instead
func (v *Vault) Delete(path string, opts DeleteOpts) error {
	path = Canonicalize(path)

	reqState := verifyStateAlive
	if opts.Destroy {
		reqState = verifyStateAliveOrDeleted
	}

	err := v.verifySecretState(path, verifyOpts{
		AnyVersion: opts.All,
		State:      reqState,
	})
	if err != nil {
		return err
	}

	err = v.canSemanticallyDelete(path)
	if err != nil {
		return err
	}

	if !PathHasKey(path) {
		return v.deleteEntireSecret(path, opts.Destroy, opts.All)
	}

	return v.deleteSpecificKey(path)
}

func (v *Vault) deleteEntireSecret(path string, destroy bool, all bool) error {
	secret, _, version := ParsePath(path)

	if destroy && all {
		return v.client.DestroyAll(secret)
	}

	var versions []uint
	if version != 0 {
		versions = []uint{uint(version)}
	}

	if destroy {
		allVersions, err := v.Versions(secret)
		if err != nil {
			return err
		}
		//Need to populate latest version to a Destroy call if the
		// version is not explicitly given
		if len(versions) == 0 {
			versions = []uint{allVersions[len(allVersions)-1].Version}
		}
		//Check if we should clean up the metadata entirely because there are
		// no more remaining non-destroyed versions
		shouldNuke := true
		verIdx := 0
		for i := range allVersions {
			for verIdx < len(versions) && versions[verIdx] < allVersions[i].Version {
				verIdx++
			}
			if !allVersions[i].Destroyed && (verIdx >= len(versions) || versions[verIdx] != allVersions[i].Version) {
				shouldNuke = false
				break
			}
		}

		if shouldNuke {
			return v.client.DestroyAll(secret)
		}
		return v.client.Destroy(secret, versions)
	}

	if all {
		allVersions, err := v.Versions(secret)
		if err != nil {
			return err
		}

		versions = make([]uint, 0, len(allVersions))
		for i := range allVersions {
			versions = append(versions, allVersions[i].Version)
		}

	}

	return v.client.Delete(secret, &vaultkv.KVDeleteOpts{Versions: versions, V1Destroy: true})
}

func (v *Vault) deleteSpecificKey(path string) error {
	secretPath, key, _ := ParsePath(path)
	secret, err := v.Read(secretPath)
	if err != nil {
		return err
	}
	deleted := secret.Delete(key)
	if !deleted {
		return NewKeyNotFoundError(secretPath, key)
	}
	if secret.Empty() {
		//Gotta avoid call to Write because Write ignores version information (with good reason)
		// We can only be here and not be on the latest version if this was the only key remaining
		// and we're just trying to nuke the secret
		//
		//At some point, we should probably get Destroy routed into here so that we can destroy
		// secrets through specifying keys
		return v.deleteEntireSecret(secretPath, false, false)
	}
	return v.Write(secretPath, secret)
}

//DeleteVersions marks the given versions of the given secret as deleted for
// a v2 backend or actually deletes it for a v1 backend.
func (v *Vault) DeleteVersions(path string, versions []uint) error {
	return v.client.Delete(path, &vaultkv.KVDeleteOpts{Versions: versions, V1Destroy: true})
}

//DestroyVersions irrevocably destroys the given versions of the given secret
func (v *Vault) DestroyVersions(path string, versions []uint) error {
	return v.client.Destroy(path, versions)
}

func (v *Vault) Undelete(path string) error {
	secret, key, version := ParsePath(path)
	if key != "" {
		return fmt.Errorf("Cannot undelete specific key (%s)", path)
	}

	err := v.verifySecretUndestroyed(path)
	if err != nil {
		return err
	}

	return v.Client().Undelete(secret, []uint{uint(version)})
}

//deleteIfPresent first checks to see if there is a Secret at the given path,
// and if so, it deletes it. Otherwise, no error is thrown
func (v *Vault) deleteIfPresent(path string, opts DeleteOpts) error {
	secretpath, _, _ := ParsePath(path)
	if _, err := v.Read(secretpath); err != nil {
		if IsSecretNotFound(err) {
			return nil
		}
		return err
	}

	err := v.Delete(path, opts)
	if IsKeyNotFound(err) {
		return nil
	}
	return err
}

func (v *Vault) verifyMetadataExists(path string) error {
	versions, err := v.Versions(path)
	if err != nil {
		if vaultkv.IsNotFound(err) {
			return NewSecretNotFoundError(path)
		}
		return err
	}

	if len(versions) == 0 {
		return NewSecretNotFoundError(path)
	}

	return nil
}

type MoveCopyOpts struct {
	SkipIfExists bool
	Quiet        bool
	//Deep copies all versions and overwrites all versions at the target location
	Deep bool
	//DeletedVersions undeletes, reads, and redeletes the deleted keys
	// It also puts in dummy destroyed keys to dest to match destroyed keys from src
	//Makes no sense without Deep
	DeletedVersions bool
}

// Copy copies secrets from one path to another.
// With a secret:key specified: key -> key is good.
// key -> no-key is okay - we assume to keep old key name
// no-key -> key is bad. That makes no sense and the user should feel bad.
// Returns KeyNotFoundError if there is no such specified key in the secret at oldpath
func (v *Vault) Copy(oldpath, newpath string, opts MoveCopyOpts) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	if opts.DeletedVersions && !opts.Deep {
		panic("Gave DeletedVersions and not Deep")
	}
	var err error
	reqState := verifyStateAlive
	if opts.DeletedVersions {
		reqState = verifyStateAliveOrDeleted
	}

	err = v.verifySecretState(oldpath, verifyOpts{
		State:      reqState,
		AnyVersion: opts.Deep,
	})
	if err != nil {
		return err
	}

	if opts.SkipIfExists {
		if _, err := v.Read(newpath); err == nil {
			if !opts.Quiet {
				ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as that would clobber existing data}\n", newpath)
			}
			return nil
		} else if !IsNotFound(err) {
			return err
		}
	}

	srcPath, srcKey, _ := ParsePath(oldpath)
	dstPath, dstKey, _ := ParsePath(newpath)

	var toWrite []*Secret
	if srcKey != "" { //Just a single key.
		if opts.Deep {
			return fmt.Errorf("Cannot take deep copy of a specific key")
		}
		srcSecret, err := v.Read(oldpath)
		if err != nil {
			return err
		}

		if !srcSecret.Has(srcKey) {
			return NewKeyNotFoundError(oldpath, srcKey)
		}

		if dstKey == "" {
			dstKey = srcKey
		}

		dstOrig, err := v.Read(dstPath)
		if err != nil && !IsSecretNotFound(err) {
			return err
		}

		if IsSecretNotFound(err) {
			dstOrig = NewSecret()
		}

		toWrite = append(toWrite, dstOrig)
		toWrite[0].Set(dstKey, srcSecret.Get(srcKey), false)
	} else {
		if dstKey != "" {
			return fmt.Errorf("Cannot move full secret `%s` into specific key `%s`", oldpath, newpath)
		}
		t, err := v.ConstructSecrets(srcPath, TreeOpts{
			FetchKeys:           true,
			GetOnly:             true,
			FetchAllVersions:    opts.Deep,
			GetDeletedVersions:  opts.Deep && opts.DeletedVersions,
			AllowDeletedSecrets: opts.Deep,
		})

		if err != nil {
			return err
		}

		err = t[0].Copy(v, dstPath, TreeCopyOpts{Clear: opts.Deep, Pad: opts.Deep})
		if err != nil {
			return err
		}
	}

	for i := range toWrite {
		err := v.Write(dstPath, toWrite[i])
		if err != nil {
			return err
		}
	}

	return nil
}

//MoveCopyTree will recursively copy all nodes from the root to the new location.
// This function will get confused about 'secret:key' syntax, so don't let those
// get routed here - they don't make sense for a recursion anyway.
func (v *Vault) MoveCopyTree(oldRoot, newRoot string, f func(string, string, MoveCopyOpts) error, opts MoveCopyOpts) error {
	oldRoot = Canonicalize(oldRoot)
	newRoot = Canonicalize(newRoot)

	tree, err := v.ConstructSecrets(oldRoot, TreeOpts{FetchKeys: false, AllowDeletedSecrets: opts.Deep, SkipVersionInfo: true})
	if err != nil {
		return err
	}
	if opts.SkipIfExists {
		//Writing one secret over a deleted secret isn't clobbering. Completely overwriting a set of deleted secrets would be
		newTree, err := v.ConstructSecrets(newRoot, TreeOpts{FetchKeys: false, AllowDeletedSecrets: !opts.Deep, SkipVersionInfo: true})
		if err != nil && !IsNotFound(err) {
			return err
		}
		existing := map[string]bool{}
		for _, path := range newTree.Paths() {
			existing[path] = true
		}
		existingPaths := []string{}
		for _, path := range tree.Paths() {
			newPath := strings.Replace(path, oldRoot, newRoot, 1)
			if existing[newPath] {
				existingPaths = append(existingPaths, newPath)
			}
		}
		if len(existingPaths) > 0 {
			if !opts.Quiet {
				ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as the following paths would be clobbered:}\n", newRoot)
				for _, path := range existingPaths {
					ansi.Fprintf(os.Stderr, "@R{- }@C{%s}\n", path)
				}
			}
			return nil
		}
	}
	for _, path := range tree.Paths() {
		newPath := strings.Replace(path, oldRoot, newRoot, 1)
		err = f(path, newPath, opts)
		if err != nil {
			return err
		}
	}

	if _, err := v.Read(oldRoot); !IsNotFound(err) { // run through a copy unless we successfully got a 404 from this node
		return f(oldRoot, newRoot, opts)
	}
	return nil
}

// Move moves secrets from one path to another.
// A move is semantically a copy and then a deletion of the original item. For
// more information on the behavior of Move pertaining to keys, look at Copy.
func (v *Vault) Move(oldpath, newpath string, opts MoveCopyOpts) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	err := v.canSemanticallyDelete(oldpath)
	if err != nil {
		return fmt.Errorf("Can't move `%s': %s. Did you mean cp?", oldpath, err)
	}
	if err != nil {
		return err
	}

	err = v.Copy(oldpath, newpath, opts)
	if err != nil {
		return err
	}

	if opts.Deep && opts.DeletedVersions {
		err = v.client.DestroyAll(oldpath)
	} else {
		err = v.Delete(oldpath, DeleteOpts{})
		if err != nil {
			return err
		}
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

func (v *Vault) FindSigningCA(cert *X509, certPath string, signPath string) (*X509, string, error) {
	/* find the CA */
	if signPath != "" {
		if certPath == signPath {
			return cert, certPath, nil
		} else {
			s, err := v.Read(signPath)
			if err != nil {
				return nil, "", err
			}
			ca, err := s.X509(true)
			if err != nil {
				return nil, "", err
			}
			return ca, signPath, nil
		}
	} else {
		// Check if this cert is self-signed If so, don't change the value
		// of s, because its already the cert we loaded in. #Hax
		err := cert.Certificate.CheckSignature(
			cert.Certificate.SignatureAlgorithm,
			cert.Certificate.RawTBSCertificate,
			cert.Certificate.Signature,
		)
		if err == nil {
			return cert, certPath, nil
		} else {
			// Lets see if we can guess the CA if none was provided
			caPath := certPath[0:strings.LastIndex(certPath, "/")] + "/ca"
			s, err := v.Read(caPath)
			if err != nil {
				return nil, "", fmt.Errorf("No signing authority provided and no 'ca' sibling found")
			}
			ca, err := s.X509(true)
			if err != nil {
				return nil, "", err
			}
			return ca, caPath, nil
		}
	}
}

func (v *Vault) SaveSealKeys(keys []string) {
	path := "secret/vault/seal/keys"
	s := NewSecret()
	for i, key := range keys {
		s.Set(fmt.Sprintf("key%d", i+1), key, false)
	}
	v.Write(path, s)
}

func (v *Vault) SetURL(u string) {
	vaultURL, err := url.Parse(strings.TrimSuffix(u, "/"))
	if err != nil {
		panic(fmt.Sprintf("Could not parse Vault URL: %s", err))
	}
	v.client.Client.VaultURL = vaultURL
}
