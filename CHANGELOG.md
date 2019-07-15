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
