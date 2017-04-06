# Click

Click is the Command Line Interactive Contoller for Kubernetes.  It's
goal is to make managing a large number of kubernetes clusters/objects
quick and efficient.

# Usage Model
Click is a REPL.  When running there is a current active config which
includes the current kubernetes context, and optionally a namespace
and kubernetes object.  Commands are then applied to the active config
so it's not necessary to keep specifying what objects to target.

# Building
Checkout the code and run `cargo build --release`.

# Running
Run `./target/release/click`.  It's not recommended to use `cargo run`
as that messes with Ctrl-C handling.

Click looks in ~/.kube/config by default for you kubernetes
configuration.  It also stores its own config in the .kube dir.  You
can change this with the --config option.

Once your in the repl, try typing `help` to see what you can do.

# Prompt
The order of the prompt is \[context\]\[namespace\]\[object\].

The object will be yellow if it's a pod, blue if it's a node.
