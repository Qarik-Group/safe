package vault

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

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
	insertInto *[]Tree
	path       string
	operation  int
}

type Tree struct {
	Name         string
	Branches     []Tree
	Type         int
	MountVersion uint
	Value        string
}

const (
	TreeTypeRoot int = iota
	TreeTypeDir
	TreeTypeSecret
	TreeTypeDirAndSecret
	TreeTypeKey
)

const (
	opTypeNone int = iota
	opTypeList
	opTypeGet
	opTypeListAndGet
	opTypeMounts
)

type TreeOpts struct {
	//For tree/paths --keys
	FetchKeys bool
	//v2 backends show deleted keys in the list
	AllowDeletedKeys bool
}

func (v *Vault) ConstructTree(path string, opts TreeOpts) (*Tree, error) {
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
	ret := &Tree{Name: path}
	err := ret.populateNodeType(v)
	if err != nil {
		return nil, err
	}
	operation := ret.getWorkType(opts)
	if err != nil {
		return nil, err
	}
	queue.Push(&workOrder{
		insertInto: &ret.Branches,
		path:       ret.Name,
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

	if !opts.AllowDeletedKeys {
		ret.pruneEmpty()
	}

	if !opts.FetchKeys {
		ret.pruneKeys()
	}

	//Make the output deterministic
	ret.sort()

	return ret, err
}

//Only use this for the base for the initial node of the tree. You can infer
// type much faster than this if you know the operation that retrieved it in the
// first place.
func (t *Tree) populateNodeType(v *Vault) error {
	if t.Name == "/" {
		t.Type = TreeTypeRoot
		return nil
	}

	_, err := v.Read(t.Name)
	if err != nil {
		if !IsNotFound(err) {
			return err
		}

		t.Type = TreeTypeDir
	} else {
		t.Type = TreeTypeSecret

		_, err := v.List(t.Name)
		if err == nil {
			t.Type = TreeTypeDirAndSecret
		}
		if err != nil && !IsNotFound(err) {
			return err
		}

	}
	return nil
}

func (t *Tree) getWorkType(opts TreeOpts) int {
	var ret int

	switch t.Type {
	case TreeTypeRoot:
		ret = opTypeMounts
	case TreeTypeDir:
		t.Name = strings.TrimRight(t.Name, "/") + "/"
		ret = opTypeList
	case TreeTypeDirAndSecret:
		ret = opTypeList
		if opts.FetchKeys || (t.MountVersion == 2 && !opts.AllowDeletedKeys) {
			ret = opTypeListAndGet
		}
	case TreeTypeSecret:
		ret = opTypeNone
		if opts.FetchKeys || (t.MountVersion == 2 && !opts.AllowDeletedKeys) {
			ret = opTypeListAndGet
		}
	}

	return ret
}

func (t Tree) Paths() []string {
	ret := make([]string, 0, 0)

	if len(t.Branches) == 0 {
		ret = append(ret, t.Name)
	} else {
		for _, branch := range t.Branches {
			ret = append(ret, branch.Paths()...)
		}
	}

	return ret
}

func (t Tree) Basename() string {
	var ret string
	switch t.Type {
	case TreeTypeRoot:
		ret = "/"
	case TreeTypeDir:
		splits := strings.Split(strings.TrimRight(t.Name, "/"), "/")
		ret = splits[len(splits)-1] + "/"
	case TreeTypeSecret, TreeTypeDirAndSecret:
		splits := strings.Split(strings.TrimRight(t.Name, "/"), "/")
		ret = splits[len(splits)-1]
	case TreeTypeKey:
		splits := strings.Split(t.Name, ":")
		ret = splits[len(splits)-1]
	}

	return ret
}

func (t *Tree) DepthFirstMap(fn func(*Tree)) {
	for i := range t.Branches {
		fn(&t.Branches[i])
		t.Branches[i].DepthFirstMap(fn)
	}
}

func (t *Tree) pruneEmpty() {
	newBranches := []Tree{}
	for i := range t.Branches {
		if t.Branches[i].MountVersion == 2 {
			t.Branches[i].pruneEmpty()
			if t.Type == TreeTypeRoot || t.Branches[i].Type == TreeTypeKey || len(t.Branches[i].Branches) > 0 {
				newBranches = append(newBranches, t.Branches[i])
			} else {
				fmt.Printf("Pruning %s\n", t.Branches[i].Name)
			}
		} else {
			newBranches = append(newBranches, t.Branches[i])
		}
	}

	t.Branches = newBranches
}

func (t *Tree) pruneKeys() {
	newBranches := []Tree{}
	for i := range t.Branches {
		t.Branches[i].pruneKeys()
		if t.Branches[i].Type != TreeTypeKey {
			newBranches = append(newBranches, t.Branches[i])
		}
	}

	t.Branches = newBranches
}

func (t *Tree) sort() {
	for i := range t.Branches {
		t.Branches[i].sort()
	}
	sort.Slice(t.Branches, func(i, j int) bool { return t.Branches[i].Name < t.Branches[j].Name })
}

func (t Tree) Draw(color bool, leaves bool) string {
	printTree := t.printableTree(color, leaves, true)
	return printTree.Draw()
}

func (t Tree) printableTree(color, leaves, root bool) *tree.Node {
	if t.Type == TreeTypeSecret && !leaves {
		return nil
	}

	name := t.Name
	if !root {
		name = t.Basename()
		if t.Type == TreeTypeKey {
			name = ":" + name
		}
	}

	const dirFmt, secFmt, keyFmt = "@B{%s}", "@G{%s}", "@Y{%s}"
	if color {
		switch t.Type {
		case TreeTypeDir, TreeTypeRoot:
			name = ansi.Sprintf(dirFmt, name)
		case TreeTypeSecret, TreeTypeDirAndSecret:
			name = ansi.Sprintf(secFmt, name)
		case TreeTypeKey:
			name = ansi.Sprintf(keyFmt, name)
		}
	}

	ret := &tree.Node{
		Name: name,
	}

	for i := range t.Branches {
		toAdd := t.Branches[i].printableTree(color, leaves, false)
		if toAdd != nil {
			ret.Append(*toAdd)
		}
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
		var answer []Tree
		switch order.operation {
		case opTypeList:
			answer, err = w.workList(order.path)
		case opTypeGet:
			answer, err = w.workGet(order.path)
		case opTypeListAndGet:
			answer, err = w.workGet(order.path)
			if err != nil {
				break
			}

			var listAnswer []Tree
			listAnswer, err = w.workList(order.path + "/")
			if err != nil {
				break
			}
			answer = append(answer, listAnswer...)
		case opTypeMounts:
			answer, err = w.workMounts()
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

		*order.insertInto = append(*order.insertInto, answer...)
		for i, node := range *order.insertInto {
			w.orders.Push(&workOrder{
				insertInto: &(*order.insertInto)[i].Branches,
				path:       node.Name,
				operation:  node.getWorkType(w.opts),
			})
		}

		order, done = w.orders.Pop()
	}

	w.errors <- nil
}

func (w *treeWorker) workList(path string) ([]Tree, error) {
	list, err := w.vault.List(path)
	if err != nil {
		//This is most likely because a mount exists but has no secrets in it yet
		// Probably shouldn't err
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	ret := []Tree{}
	for _, l := range list {
		t := TreeTypeSecret
		if strings.HasSuffix(l, "/") {
			t = TreeTypeDir
		}
		ret = append(ret, Tree{
			Name: strings.TrimRight(path, "/") + "/" + l,
			Type: t,
		})
	}

	return ret, nil
}

func (w *treeWorker) workGet(path string) ([]Tree, error) {
	mountVersion, err := w.vault.MountVersion(path)
	if err != nil {
		return nil, err
	}

	s, err := w.vault.Read(path)
	if err != nil {
		//List returns keys marked as deleted in KV v2 backends, such
		// that Get would 404 on trying to follow the listing.
		if IsNotFound(err) && mountVersion == 2 {
			return nil, nil
		}
		return nil, err
	}

	ret := []Tree{}
	for _, key := range s.Keys() {
		ret = append(ret, Tree{
			Name:  path + ":" + key,
			Type:  TreeTypeKey,
			Value: s.data[key],
		})
	}

	return ret, nil
}

func (w *treeWorker) workMounts() ([]Tree, error) {
	generics, err := w.vault.Mounts("generic")
	if err != nil {
		return nil, err
	}

	kvs, err := w.vault.Mounts("kv")
	if err != nil {
		return nil, err
	}

	mounts := append(kvs, generics...)

	ret := []Tree{}
	for _, mount := range mounts {
		ret = append(ret, Tree{
			Name: mount + "/",
			Type: TreeTypeDir,
		})
	}

	return ret, nil
}
