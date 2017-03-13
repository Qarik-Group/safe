go-cli
======

Rite-of-passage-style Go command line parser.

CLIs are awesome.  Most options libraries aren't.  `go-cli`
doesn't attempt to change that, it just tries to focus on doing
one thing well.

Things you **will not** find in `go-cli`:

  - Magical bash/zsh Auto-completion support
  - Usage generation
  - Option help string
  - Option defaults

Things you **will** find in `go-cli`:

  - A dead-simple, tagged-struct approach to options
  - A rudimentary sub-command recognizer
  - A flexible argument processor

Usage
=====

Should be pretty simple.

```
import (
  "fmt"
  "os"

  "github.com/jhunt/go-cli"
)

type Options struct {
  Help     bool   `cli:"-h, --help"`
  Version  bool   `cli:"-v, --version"`
  Insecure bool   `cli:"-k, --insecure, --no-insecure"`
  URL      string `cli:"-U, --url"`

  Gen struct {
    Length int     `cli:"-l, --length"`
    Policy string  `cli:"-p, --policy"`
  } `cli:"gen"`
}

func main() {
  var options Options
  options.Gen.Length = 48 // a default

  command, args, err := cli.Parse(&options)
  if err != nil {
    fmt.Fprintf(os.Stderr, "!!! %s\n", err)
    os.Exit(1)
  }

  if command == "gen" {
    fmt.Printf("generating a password %d characters long", options.Gen.Length)
    // ...
  }
}
```

Repeat Flags
============

If you assign a `cli:"..."` tag to a slice (`[]thing`) in your
options structure, `go-cli` allows users to specify that flag
multiple times, and will combine all of the given values, in
order, into a list and assign that to the slice.

Here, I have to point out that you _can_ supply a default value
for a repeat flag by assigning to the slice before telling
`go-cli` about it, but the semantics of override bear some
thought.

The easiest case to implement is that command-line flags append to
the default value.  That works great for the no-defaults case,
since appending to an empty list just allocates a new list.  But
that means that users of the program can never escape the
_default_ choices made by the programmer.

Instead, `go-cli` uses the default as-is, until the first time it
sees an instance of that flag on the actual command line.  At that
point, it chucks the default out the window, allocates a fresh
slice, and begins assembling values.

So, remember: **defaults for repeat flags get thrown out upon
override**!

Reusing Flags
=============

You can reuse option flags, both short and long, as long as it is
provable unambiguous where and when callers can use the flag.
Practically, this means:

  1. You cannot reuse flags defined "above" you
  2. You cannot reuse flags on the same level as you

This allows `go-cli` to recognize arguments for a single level
(global, sub-command, sub-sub-command, ad infinitum) at any point
after the "beginning" of that level.

Let's look at some examples, shall we?

```
type Options struct {
  Help   bool           `cli:"-h, --help"`

  List struct {
    LongForm   bool     `cli:"-l, --long"`
    All        bool     `cli:"-a, --all"`
  } `cli:"list, ls"`

  Create struct {
    Archive    string   `cli:"-a, "--archive"`
    Name       string   `cli:"-n, "--name"`
  } `cli:"new"`
}
```

Here, `-h` / `--help` is _global option_.  It can appear anywhere
in the command line invocation, and it has the same semantics
everywhere (namely, to show the help or something).

On the contrary, `-l` / `--long` only makes sense after the `list`
sub-command.  If encountered before `list`, it's an unrecognized
flag.

The up-shot of this is that a user of your CLI can do this:

```
$ ./foo -h
$ ./foo list -h
$ ./foo ls -h
$ ./foo list -h --all
$ ./foo -h list -h --all -h
```

This is why you can't override the `-h` / `--help` flag on a
per-command basis -- it's just too confusing to end users
(including the author of `go-cli`).

If you look closely, you'll notice that both `list` and `new`
define a `-a` short option.  What gives?  Didn't this guy _just
get done saying that you can't override flags??_

It's cool.  It's going to be alright.  There's not much chance of
a user conflating the two `-a` use cases - `list -a` lists
everything, but `new -a name` sets an archive name.  And since
`-a` doesn't exist at the global level ("above"), you can't do
this:

```
$ ./foo -a list                 # this is bad
```

So, without any ambiguity, `go-cli` is perfectly happy to let you
overload the meaning of `-a`.  Whether you _should_, is entirely
up to you.

Chained Commands
================

A curiously powerful command-line paradigm involves abusing the
`--` signifier to _chain commands_.  That is, within a single
executed process, do a whole bunch of sub-commands, like this:

```
$ ./cli -t prod --format silent -k \
      set system.cores.available 4 \
   -- set system.cores.usable 2 --if-missing \
   -- build vm --name new-vm --ip 10.40.0.5/24 \
   -- list --format fancy --all
```

`go-cli` tries very hard to make this style of CLI interaction
both easy to program, and simple and unsurprising to use.  A few
things to keep in mind:

Global options specified before any sub-commands will be treated
as truly global; every single sub-command will inherit the values
set _globally_.  That's not to say each sub-command is stuck with
what was specified at the global level.  Nope.  Sub-commands can
provide their own values for global options.  The `list` command
in the above example undoes the global `--format` with it's own
definition as 'fancy'.

Options set for a given sub-command only affect that instance of
that sub-command.  This mimics how normal shells operate.  Running
`ls -r` followed by an `rm` isn't going to magically cause your
`rm` to become recursive.  In the example above, the second `set`
sub-command runs with the `--if-missing` option set to true, but
that doesn't affect the first `set` (nor any future `set`s).

Similarly, overriding a global option for a sub-command _only
persists for the scope of that sub-command_.

The idiom for supporting chained sub-command calls is short and
sweet:

```
p, err := cli.NewParser(&opts, os.Args)
if err != nil {
  panic(err)
}

for p.Next() {
  // dispatch on the value of p.Command and p.Args
}

if err = p.Error(); err != nil {
  panic(err)
}
```

Error checking is **very important** here; we check errors in two
places: when we create the parser via `cli.NewParser()`, and once
we stop processing chained commands.  The former region of code
can error if global option parsing fails (unrecognized flag,
missing value argument, etc).  The latter can fail if sub-command
option parsing fails (unrecognized sub-command, bad flag, missing
value, etc).  If you skip either case for error checking, you are
doing your users a great disservice.

The loop in the middle is the workhorse of the idiom.  `p.Next()`
will return true as long as it finds the next sub-command to run.
Once it runs out of chained sub-commands, or encounters an error,
it returns false.

Inside the body of the loop, you can access `p.Command` to get the
full, space-separated name of the sub-command to run.  Aliases
(i.e. 'ls' in `cli:"list, ls"`) will be resolved to the first name
in the tag list (here, "list"). `p.Args` will give you the list of
positional arguments, in the order they were specified, with all
of the `-s` and `--style` flags removed.

Note that any changes you make to the option structure between
subsequent calls to `Next()` will be lost by virtue of the
snapshotting / reset features that make this whole magic show
work.  The same goes for changes between calling `NewParser()` and
the first `Next()` call.

Contributing
============

This code is licensed MIT.  Enjoy.

If you find a bug, please raise a [Github Issue][issues] first,
before submitting a PR.

When you do work up a patch, keep in mind that we have a fairly
extensive test suite in `cli_test.go`.  I don't care _all that
much_ about code coverage, but we do have >90% C0 code coverage on
the current tests suite, and I'd like to keep it that way.

(That's not to say we've caught 90% of the bugs, but it's better
than nothin')

Happy Hacking!

