package vault

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
	"github.com/starkandwayne/goutils/tree"
)

//This is a synchronized queue that specifically works with our tree algorithm,
// in which the workers that pull work off the queue are also responsible for
// populating the queue. This is because of the recursive nature of the tree
// population. All workers are released when all workers are simultaneously
// waiting on an empty queue.
type workQueue struct {
	head   *workQueueNode
	tail   *workQueueNode
	c      *sync.Cond
	awake  int
	closed bool
}

type workQueueNode struct {
	next    *workQueueNode
	payload *workOrder
}

func newWorkQueue(numWorkers int) *workQueue {
	return &workQueue{
		c:     sync.NewCond(&sync.Mutex{}),
		awake: numWorkers,
	}
}

func (w *workQueue) Pop() (ret *workOrder, done bool) {
	w.c.L.Lock()
	//While it'd be more "correct" logically to put this inside the loop, its a
	// minor optimization to keep it outside - it all looks the same transactionally
	// anyway
	w.awake--
	for w.head == nil && !w.closed {
		//This would mean that all the workers would be waiting for something new
		// to enter the queue. Given that the workers are also responsible for
		// populating the queue, this means that nothing else can possibly enter
		// and that we're done
		if w.awake == 0 {
			w.closed = true
			w.c.Broadcast()
			break
		}

		w.c.Wait()
	}
	if w.closed {
		w.c.L.Unlock()
		return nil, true
	}

	w.awake++

	ret = w.head.payload
	w.head = w.head.next
	if w.head == nil {
		w.tail = nil
	}

	w.c.L.Unlock()
	return ret, false
}

func (w *workQueue) Push(o *workOrder) {
	w.c.L.Lock()
	if w.closed {
		w.c.L.Unlock()
		return
	}

	toAdd := &workQueueNode{payload: o}

	if w.tail != nil {
		w.tail.next = toAdd
	} else { //tail is nil iff head is nil
		w.head = toAdd
	}

	w.tail = toAdd

	w.c.L.Unlock()
	w.c.Signal()
}

func (w *workQueue) Close() {
	w.c.L.Lock()
	if !w.closed {
		w.closed = true
		w.c.Broadcast()
	}
	w.c.L.Unlock()
}

type workOrder struct {
	insertInto *secretTree
	operation  uint16
}

type secretTree struct {
	Name         string
	Branches     []secretTree
	Type         uint
	MountVersion uint
	Value        string
	Version      uint
	Deleted      bool
	Destroyed    bool
}

func (v *Vault) ConstructSecrets(path string, opts TreeOpts) (s Secrets, err error) {
	constructTreeOpts := opts
	//It's easier to analyze which secrets to purge once we have it structured as an array.
	//So we let the tree just naively fetch secrets, and then we can clean up the results later
	constructTreeOpts.SkipVersionInfo = opts.AllowDeletedSecrets && opts.SkipVersionInfo
	t, err := v.constructTree(path, constructTreeOpts)
	if err != nil {
		return nil, err
	}

	s = t.convertToSecrets()
	if !opts.AllowDeletedSecrets {
		s.purgeWhereLatestVersionDeleted()
	}
	//If we populated versions earlier and it wasn't asked for directly, lets clean them up now
	if opts.SkipVersionInfo {
		s.purgeVersions()
	}

	s.Sort()
	return s, nil
}

//This does not keep the list in a sorted order. Sort afterward
func (s *Secrets) purgeWhereLatestVersionDeleted() {
	for i := 0; i < len(*s); i++ {
		if len((*s)[i].Versions) == 0 || (*s)[i].Versions[len((*s)[i].Versions)-1].State != SecretStateAlive {
			(*s)[i], (*s)[len(*s)-1] = (*s)[len(*s)-1], (*s)[i]
			*s = (*s)[:len(*s)-1]
			i--
		}
	}
}

func (s *Secrets) purgeVersions() {
	for i := range *s {
		(*s)[i].Versions = nil
	}
}

func PathLessThan(left, right string) bool {
	leftSplit := strings.Split(Canonicalize(left), "/")
	rightSplit := strings.Split(Canonicalize(right), "/")

	minLen := len(leftSplit)
	if len(rightSplit) < minLen {
		minLen = len(rightSplit)
	}

	for i := 0; i < minLen; i++ {
		if leftSplit[i] < rightSplit[i] {
			return true
		} else if leftSplit[i] > rightSplit[i] {
			return false
		}
	}

	if len(left) < len(right) {
		return true
	} else if len(left) > len(right) {
		return false
	}

	return !strings.HasSuffix(left, "/")
}

func (s Secrets) Sort() {
	sort.Slice(s, func(i, j int) bool { return PathLessThan(s[i].Path, s[j].Path) })
}

func (s1 Secrets) Merge(s2 Secrets) Secrets {
	ret := append(Secrets{}, s1...)
	for _, s := range s2 {
		idx := sort.Search(len(ret), func(i int) bool {
			return (s.Path == ret[i].Path || PathLessThan(s.Path, ret[i].Path))
		})
		if idx == len(ret) {
			ret = append(ret, s)
			continue
		}

		if s.Path == ret[idx].Path {
			continue
		}

		before := ret[:idx]
		after := append(Secrets{s}, ret[idx:]...)
		ret = append(before, after...)
	}

	return ret
}

func (t secretTree) convertToSecrets() Secrets {
	var ret Secrets
	t.DepthFirstMap(func(t *secretTree) {
		if t.Type == treeTypeSecret || t.Type == treeTypeDirAndSecret {
			thisEntry := SecretEntry{
				Path: Canonicalize(t.Name),
			}

			for _, version := range t.Branches {
				if version.Type != treeTypeVersion {
					continue
				}

				thisVersion := SecretVersion{
					Data:   NewSecret(),
					Number: version.Version,
					State:  SecretStateAlive,
				}

				if version.Destroyed {
					thisVersion.State = SecretStateDestroyed
				} else if version.Deleted {
					thisVersion.State = SecretStateDeleted
				}

				for _, key := range version.Branches {
					thisVersion.Data.Set(key.Basename(), key.Value, false)
				}

				thisEntry.Versions = append(thisEntry.Versions, thisVersion)
			}

			ret = append(ret, thisEntry)
		}
	})

	return ret
}

const (
	treeTypeRoot uint = iota
	treeTypeDir
	treeTypeSecret
	treeTypeDirAndSecret
	treeTypeKey
	treeTypeVersion
)

const (
	opTypeNone uint16 = 0
	opTypeList        = 1 << (iota - 1)
	opTypeGet
	opTypeMounts
	opTypeVersions
)

type Secrets []SecretEntry

func (s *Secrets) Append(e SecretEntry) {
	*s = append(*s, e)
}

type SecretEntry struct {
	Path     string
	Versions []SecretVersion
}

const (
	SecretStateAlive uint = iota
	SecretStateDeleted
	SecretStateDestroyed
)

type SecretVersion struct {
	Data   *Secret
	Number uint
	State  uint
}

type TreeOpts struct {
	//For tree/paths --keys
	FetchKeys bool
	//v2 backends show deleted secrets in the list by default
	//Leaving this unset will cause entries with the latest
	//version deleted to be purged
	//Ignored by constructTree. Just used by ConstructSecrets
	AllowDeletedSecrets bool
	//Overridden by FetchKeys
	SkipVersionInfo bool
	//Whether to get all versions of keys in the tree
	FetchAllVersions bool
	//GetDeletedVersions tells the workers to temporarily undelete deleted
	// keys to fetch their value, then delete them again
	GetDeletedVersions bool
	//Only perform gets. If the target is not a secret, then an error is returned
	GetOnly bool
}

func (v *Vault) constructTree(path string, opts TreeOpts) (*secretTree, error) {
	//3 is what I found to be the fastest in testing. Seems dumb but... works, I guess.
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}
	if numWorkers > 3 {
		numWorkers = 3
	}

	queue := newWorkQueue(numWorkers)
	errChan := make(chan error)

	path = Canonicalize(path)
	if path == "" {
		path = "/"
	}
	ret := &secretTree{Name: path}
	err := ret.populateNodeType(v)
	if err != nil {
		return nil, err
	}
	if opts.GetOnly && !(ret.Type == treeTypeSecret || ret.Type == treeTypeDirAndSecret) {
		return nil, fmt.Errorf("`%s' is not a secret", path)
	}
	operation := ret.getWorkType(opts)
	if err != nil {
		return nil, err
	}
	queue.Push(&workOrder{
		insertInto: ret,
		operation:  operation,
	})

	for i := 0; i < numWorkers; i++ {
		worker := treeWorker{
			vault:  v,
			orders: queue,
			errors: errChan,
			opts:   opts,
		}
		go worker.work()
	}

	//Workers return on errChan when they finish. They'll throw back nil if no
	// errors were encountered
	for i := 0; i < numWorkers; i++ {
		thisErr := <-errChan
		if thisErr != nil {
			err = thisErr
		}
	}
	if err != nil {
		return nil, err
	}

	//Make the output deterministic
	ret.sort()

	return ret, err
}

//Only use this for the base for the initial node of the tree. You can infer
// type much faster than this if you know the operation that retrieved it in the
// first place.
func (t *secretTree) populateNodeType(v *Vault) error {
	if t.Name == "/" {
		t.Type = treeTypeRoot
		return nil
	}

	var err error
	t.MountVersion, err = v.MountVersion(t.Name)
	if err != nil {
		return err
	}

	_, _, version := ParsePath(t.Name)
	if version > 0 {
		_, err = v.Read(t.Name)
		if err != nil {
			return err
		}
	}

	err = v.verifyMetadataExists(t.Name)
	if err != nil {
		if vaultkv.IsForbidden(err) {
			tokenerr := v.Client().Client.TokenIsValid()
			if tokenerr != nil {
				return err
			}
		} else if !IsNotFound(err) {
			return err
		}

		_, err := v.List(t.Name)
		if err != nil {
			return err
		}
		t.Type = treeTypeDir
	} else {
		t.Type = treeTypeSecret

		_, err := v.List(t.Name)
		if err == nil {
			t.Type = treeTypeDirAndSecret
		}
		if err != nil && !IsNotFound(err) {
			return err
		}

	}
	return nil
}

func (t *secretTree) getWorkType(opts TreeOpts) uint16 {
	ret := opTypeNone

	switch t.Type {
	case treeTypeRoot:
		ret = opTypeMounts
	case treeTypeDir:
		t.Name = strings.TrimRight(t.Name, "/") + "/"
		ret = opTypeList
	case treeTypeDirAndSecret:
		ret = opTypeList
		if opts.FetchKeys || !opts.SkipVersionInfo {
			ret |= opTypeVersions
		}
	case treeTypeSecret:
		if opts.FetchKeys || !opts.SkipVersionInfo {
			ret |= opTypeVersions
		}
	case treeTypeVersion:
		if opts.FetchKeys && (opts.GetDeletedVersions || !(t.Deleted || t.Destroyed)) {
			ret = opTypeGet
		}
	}

	if opts.GetOnly {
		ret &= (opTypeList ^ 0xFFFF)
	}

	return ret
}

func (s Secrets) Paths() []string {
	ret := make([]string, 0, 0)

	for i := range s {
		if len(s[i].Versions) > 0 {
			for _, key := range s[i].Versions[len(s[i].Versions)-1].Data.Keys() {
				ret = append(ret, fmt.Sprintf("%s:%s", s[i].Path, key))
			}
		} else {
			ret = append(ret, s[i].Path)
		}
	}

	return ret
}

type TreeCopyOpts struct {
	//Clear will wipe the secret in place
	Clear bool
	//Pad will insert dummy versions that have been truncated by Vault
	Pad bool
}

func (s SecretEntry) Copy(v *Vault, dst string, opts TreeCopyOpts) error {
	if opts.Clear {
		err := v.Client().DestroyAll(dst)
		if err != nil {
			return fmt.Errorf("Could not wipe existing secret at path `%s': %s", dst, err)
		}
	}

	var toDelete, toDestroy []uint

	if opts.Pad && len(s.Versions) > 0 {
		for i := uint(1); i < s.Versions[0].Number; i++ {
			setMeta, err := v.Client().Set(dst, map[string]string{"TO_DESTROY": "TO_DESTROY"}, nil)
			if err != nil {
				return fmt.Errorf("Could not write secret to path `%s': %s", dst, err)
			}

			toDestroy = append(toDestroy, setMeta.Version)
		}
	}

	for _, version := range s.Versions {
		var toWrite map[string]string
		if version.State == SecretStateDestroyed {
			toWrite = map[string]string{"TO_DESTROY": "TO_DESTROY"}
		} else {
			toWrite = version.Data.data
		}

		setMeta, err := v.Client().Set(dst, toWrite, nil)
		if err != nil {
			return fmt.Errorf("Could not write secret to path `%s': %s", dst, err)
		}

		if version.State == SecretStateDestroyed {
			toDestroy = append(toDestroy, setMeta.Version)
		} else if version.State == SecretStateDeleted {
			toDelete = append(toDelete, setMeta.Version)
		}
	}

	if len(toDestroy) > 0 {
		err := v.Client().Destroy(dst, toDestroy)
		if err != nil {
			return fmt.Errorf("Could not destroy versions %+v at path `%s': %s", toDestroy, dst, err)
		}
	}
	if len(toDelete) > 0 {
		err := v.DeleteVersions(dst, toDelete)
		if err != nil {
			return fmt.Errorf("Could not delete versions %+v at path `%s': %s", toDelete, dst, err)
		}
	}

	return nil
}

func (t secretTree) Basename() string {
	var ret string
	switch t.Type {
	case treeTypeRoot:
		ret = "/"
	case treeTypeDir:
		splits := strings.Split(strings.TrimRight(t.Name, "/"), "/")
		ret = splits[len(splits)-1] + "/"
	case treeTypeSecret, treeTypeDirAndSecret:
		splits := strings.Split(strings.TrimRight(t.Name, "/"), "/")
		ret = splits[len(splits)-1]
	case treeTypeKey:
		splits := strings.Split(t.Name, ":")
		ret = splits[len(splits)-1]
	}

	return ret
}

func (t *secretTree) DepthFirstMap(fn func(*secretTree)) {
	fn(t)
	for i := range t.Branches {
		(&t.Branches[i]).DepthFirstMap(fn)
	}
}

func (s SecretEntry) Basename() string {
	parts := strings.Split(s.Path, "/")
	return parts[len(parts)-1]
}

func (t *secretTree) sort() {
	for i := range t.Branches {
		t.Branches[i].sort()
	}
	sort.Slice(t.Branches, func(i, j int) bool {
		if t.Branches[i].Name == t.Branches[j].Name {
			return t.Branches[i].Version < t.Branches[j].Version
		}
		return t.Branches[i].Name < t.Branches[j].Name
	})
}

func (s Secrets) Draw(root string, color, secrets bool) string {
	if len(s) == 0 {
		return ""
	}

	root = strings.Trim(Canonicalize(root), "/")
	var index int
	if len(root) > 0 {
		index = len(strings.Split(root, "/"))
	}

	printTree := s.printableTree(color, secrets, index)

	root = strings.Trim(root, "/")
	if root != strings.Trim(s[0].Path, "/") {
		root = strings.TrimSuffix(root, "/") + "/"
	}
	if color {
		root = ansi.Sprintf("@C{%s}", root)
	}
	printTree.Name = root
	return printTree.Draw()
}

func (s Secrets) printableTree(color, secrets bool, index int) *tree.Node {
	if len(s) == 0 {
		return nil
	}

	//The leading slash is to simulate a root node
	firstSplit := strings.Split("/"+s[0].Path, "/")
	thisName := firstSplit[index]
	if index == 0 {
		thisName = "/"
	}
	isSecret := index == len(firstSplit)-1

	var dirFmt, secFmt, keyFmt = "%s/", "%s", ":%s"
	if color {
		dirFmt, secFmt, keyFmt = "@B{%s/}", "@G{%s}", "@Y{:%s}"
	}

	if isSecret {
		thisName = ansi.Sprintf(secFmt, thisName)
	} else {
		thisName = ansi.Sprintf(dirFmt, thisName)
	}

	ret := &tree.Node{
		Name: thisName,
	}

	if isSecret {
		if len(s[0].Versions) > 0 {
			for _, k := range s[0].Versions[len(s[0].Versions)-1].Data.Keys() {
				ret.Append(tree.Node{Name: ansi.Sprintf(keyFmt, k)})
			}
		}
	}

	//Now we need to simulate walking the "tree" by treating groups of the same
	// directory as "nodes in a tree" and thus grouping them into the next recursive call
	startIndex := 0
	if isSecret {
		startIndex = 1
	}
	for startIndex < len(s) {
		thisSplit := strings.Split("/"+s[startIndex].Path, "/")
		groupWord := thisSplit[index+1]
		//Make a separate entry for the secret
		if len(thisSplit) == index+2 {
			if secrets {
				toAdd := s[startIndex:startIndex+1].printableTree(color, secrets, index+1)
				if toAdd != nil {
					ret.Append(*toAdd)
				}
			}
			startIndex++
			continue
		}

		endIndex := startIndex + 1
		//then check for things under the "directory"
		//Determine end of this "branch"
		for ; endIndex < len(s); endIndex++ {
			thisSplit := strings.Split("/"+s[endIndex].Path, "/")
			if thisSplit[index+1] != groupWord {
				break
			}
		}

		toAdd := s[startIndex:endIndex].printableTree(color, secrets, index+1)
		if toAdd != nil {
			ret.Append(*toAdd)
		}

		startIndex = endIndex
	}

	return ret
}

type treeWorker struct {
	vault  *Vault
	orders *workQueue
	errors chan error
	opts   TreeOpts
}

func (w *treeWorker) work() {
	var err error
	handleError := func() {
		w.orders.Close()
		w.errors <- err
		//This will decrement the awake counter and exit
		//Doesn't actually Pop because we called Close
		w.orders.Pop()
	}

	order, done := w.orders.Pop()
	for !done {
		var answer []secretTree
		var toAppend []secretTree
		for _, op := range []struct {
			code uint16
			fn   func(secretTree) ([]secretTree, error)
		}{
			{opTypeGet, w.workGet},
			{opTypeList, w.workList},
			{opTypeMounts, w.workMounts},
			{opTypeVersions, w.workVersions},
		} {
			if order.operation&op.code == opTypeNone {
				continue
			}
			toAppend, err = op.fn(*order.insertInto)
			if err != nil {
				break
			}
			//toAppend can be nil if a get was issued on a destroyed node
			if toAppend != nil {
				answer = append(answer, toAppend...)
			}
		}
		if err != nil {
			handleError()
			return
		}

		for i := range answer {
			answer[i].MountVersion, err = w.vault.MountVersion(answer[i].Name)
			if err != nil {
				handleError()
				return
			}
		}

		order.insertInto.Branches = append(order.insertInto.Branches, answer...)
		for i, node := range order.insertInto.Branches {
			w.orders.Push(&workOrder{
				insertInto: &(order.insertInto.Branches[i]),
				operation:  node.getWorkType(w.opts),
			})
		}

		order, done = w.orders.Pop()
	}

	w.errors <- nil
}

func (w *treeWorker) workList(t secretTree) ([]secretTree, error) {
	path := strings.TrimSuffix(t.Name, "/")
	list, err := w.vault.List(path)
	if err != nil {
		//This is most likely because a mount exists but has no secrets in it yet
		// Probably shouldn't err
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	ret := []secretTree{}

	//This is what happens when you list a mount point which has a secret
	// at its root. We end up detecting it twice. This will ignore finding it
	// out of the list so we only find it once.
	if len(list) > 0 && list[0] == "" {
		list = list[1:]
	}
	for _, l := range list {
		t := treeTypeSecret
		if strings.HasSuffix(l, "/") {
			t = treeTypeDir
		}
		ret = append(ret, secretTree{
			Name: strings.TrimRight(path, "/") + "/" + l,
			Type: t,
		})
	}

	return ret, nil
}

func (w *treeWorker) workGet(t secretTree) ([]secretTree, error) {
	if t.Destroyed {
		return nil, nil
	}
	path := t.Name
	var err error

	if t.Deleted && !w.opts.GetDeletedVersions {
		return nil, nil
	}
	if t.Deleted {
		err = w.vault.Undelete(EncodePath(path, "", uint64(t.Version)))
		if err != nil {
			return nil, err
		}
	}

	s, err := w.vault.Read(EncodePath(path, "", uint64(t.Version)))
	if err != nil {
		return nil, err
	}

	if t.Deleted {
		w.vault.client.Delete(path, &vaultkv.KVDeleteOpts{Versions: []uint{t.Version}})
		if err != nil {
			return nil, err
		}
	}

	version := t.Version
	//If this is a v1 backend, the parent would be a secret node without a version
	if version == 0 {
		version = 1
	}

	ret := []secretTree{}
	for _, key := range s.Keys() {
		ret = append(ret, secretTree{
			Name:    path + ":" + key,
			Type:    treeTypeKey,
			Value:   string(s.data[key]),
			Version: version,
			Deleted: t.Deleted,
		})
	}

	return ret, nil
}

func (w *treeWorker) workMounts(_ secretTree) ([]secretTree, error) {
	generics, err := w.vault.Mounts("generic")
	if err != nil {
		return nil, err
	}

	kvs, err := w.vault.Mounts("kv")
	if err != nil {
		return nil, err
	}

	mounts := append(kvs, generics...)

	ret := []secretTree{}
	for _, mount := range mounts {
		//Handle the case in which a mount has a secret at its root
		if _, err = w.vault.Read(mount); err == nil {
			ret = append(ret, secretTree{
				Name: mount,
				Type: treeTypeSecret,
			})
		} else if !IsNotFound(err) {
			return nil, err
		}

		ret = append(ret, secretTree{
			Name: mount + "/",
			Type: treeTypeDir,
		})
	}

	return ret, nil
}

func (w *treeWorker) workVersions(t secretTree) ([]secretTree, error) {
	path := t.Name
	//If we've gotten this far, we know that this secret exists if the backend is v1
	// and a v1 backend can only have one version
	if t.MountVersion != 2 {
		return []secretTree{
			{
				Name:    t.Name,
				Type:    treeTypeVersion,
				Version: 1,
			},
		}, nil
	}

	versions, err := w.vault.Versions(path)
	if err != nil {
		return nil, err
	}

	ret := []secretTree{}
	for i := range versions {
		ret = append(ret, secretTree{
			Name:      t.Name,
			Type:      treeTypeVersion,
			Version:   versions[i].Version,
			Deleted:   versions[i].Deleted,
			Destroyed: versions[i].Destroyed,
		})
	}

	if !w.opts.FetchAllVersions {
		ret = ret[len(ret)-1:]
	}

	return ret, nil
}
