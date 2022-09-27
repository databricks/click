0.6.2
=====
Features:
* Allow setting the path to the kubectl binary that click uses via `set kubectl_binary <path>`
* Print the full path the kubectl binary in `env`

Bug Fixes:
* Don't panic if an "azure-auth-provider" doesn't include `expires-by`

0.6.1
=====
Bugfix release:
* Reqwest on osx seems to not support parsing multiple certs in one string, so we split them up and
  add them to the reqwest client one at a time

0.6.0
=====
Features:
* Migrate to k8s-openapi
  * This enabled a migration to reqwest and dropping of the old un-maintained http clients
    previously in use
* Update to Rust 2021 edition
* Add a `cp` command to copy files to/from a pod
* Add a `daemonsets` command
* ADd a `persistentvolumes` command
* Forward environment variables to exec'd commands (Thanks @wchau)
* All objects have a basic describe for (at least) their metadata
* Support azure and oidc auth providers (beta)
* `pods` command can show last restart time of a pod
* Migrate to comfy-table since prettytable is no longer maintained
  * As a result wide tables should render much more pleasantly
* `describe` also shows events
* Add support to show CRDs (see `help crd`)

Bug Fixes:
* Tab completion works for most arguments
* `exec` handles multi-argument commands properly
* Events sort properly in time order

0.5.4
======
* Contexts complete in alphabetical order (thanks @markj-db)
* `events` command returns events in order (based on time)
* Switch to github actions instead of travis CI

0.5.3
======
* Fix hyper-rust-tls version issue (thanks @schuermannator)
* `events` now deals with fields that can be missing

0.5.2
======
* Fix issues #140 (invalid default timeouts) and #141 (Poor experience when kubectl isn't in path)
* Switch to call kubectl exec with `--` before the command since the old way is deprecated

0.5.1
======
Small bugfix release, fixing issue with `delete`

0.5.0
======
This release includes two major new features, ranges and an --exec command. It also has lots of
small fixes and cleanup.

Features:
* Ranges: Type `help ranges` at the prompt for details. In a nutshell, you can now select multiple
  objects at once and operate on all of them.
* `--exec` can now be passed to run a one off command (useful for using click in scripts)
* The kubernetes "exec-provider" style config is now fully supported, which should fix a number of
  authentication issues.

Bug fixes:
* Set timeouts properly for all requests (especially for logs)

0.4.3
=====

Cleanup:
* cargo fmt
* lots of small changes for new compiler+clippy lints
* Adding unit tests
* Update lots of dependent crates

Bug Fixes:
* Update to compile with new duct
* The update of rustyline fixes a problem where Click would exit if you typed anything while a
  network request was processing

Changes:
* Exit when typing Ctrl-D

0.4.2
=====

Bug Fixes:
* Don't crash if `context` command is called with no arguments and there's a context with no cluster
* Update rustyline version so it actually compiles


0.4.1
=====

Cleanup:
* Move config module into its own dir
* Update duct so things compile properly

Bug Fixes:
* Handle minikube certs by working around webpki's lack of support for IpAddress SANS

0.4.0
=====
This is a fairly substantial release, and includes a number of enhancements and bug fixes. Some of
the more notable ones are listed below.

Feature enhancements:

* Add an `alias` command, which works similarly to a bash alias. See `help alias`
* The `pods`, `services`, `deployments`, and `nodes` commands support outputting the list in a
  sorted manner via a `-s/--sort` flag.  See the help for each command for details
* The `pods` command can now show the node each pod is on via `-n/--show-node`
* `describe` can now output yaml with -y/--yaml
* Readline style completion.  See `help completion`
* Completion support for options. `[command] --<TAB>` will complete
* Support for Emacs or Vi style editing.  See `help edit_mode`
* Support for Jobs
* Support for StatefulSets
* Support multiple files in `KUBECONFIG` similarly to kubectl

Bug Fixes and Updated Libraries:

* click.config is written more often and safely to prevent unexpected loss of aliases or context
  changes
* `rustyline` -> 0.3.0: this allows a much richer command line interaction. see `help edit_mode` and
  `help completion`
* `dir`: move away from deprecated `std::env` for getting home directory
* `hyper-sync-rustls`: updates `untrused`, which had a security vulnerability (see Issue #66)

0.3.2
=====
Feature enhancements:

* `ctx` with no args prints all contexts
* `logs` on a pod with a single container defaults to that container
* show token in secret description
* Support for gke authentication
* support insecure\_skip\_tls\_verify in config
* use KUBECONFIG environment variable to identify config file

Bug Fixes:
* `logs` command now works for clusters using an IP address
* remove a number of unwraps that could cause unhelpful panics

0.3.1
=====
Feature enhancements:

* Support for ConfigMaps
* Support describe Secrets
* -e option for opening `logs` in an editor
* Support `delete` on more items
* Option to run `exec` in a new terminal
* Support username/password login

0.3.0
=====
First public release
