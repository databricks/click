# Click

Click is the Command Line Interactive Contoller for Kubernetes.  It's
goal is to make managing a large number of kubernetes clusters/objects
quick and efficient.

<a href="http://i.imgur.com/rg2UYjV.png"><img src="http://i.imgur.com/rg2UYjV.png" width="1024"></a>

# Usage Model
Click is a REPL.  When running there is a current active config which
includes the current kubernetes context, and optionally a namespace
and kubernetes object.  Commands are then applied to the active config
so it's not necessary to keep specifying what objects to target.

[Here's a little demo gif that shows a few features](https://gfycat.com/AgitatedFlusteredFeline)

# Building
You'll need rust and cargo.  See [here](http://doc.crates.io/) for
instructions on how to do that.

Checkout the code and run `cargo build`.

# Running
Run `./target/debug/click`.  It's not recommended to use `cargo run`
as that messes with Ctrl-C handling. (see:
https://github.com/rust-lang-nursery/rustup.rs/issues/806)

Click looks in ~/.kube/config by default for you kubernetes
configuration.  It also stores its own config in the .kube dir.  You
can change this with the --config option.

Once your in the repl, try typing `help` to see what you can do.

# Prompt
The order of the prompt is \[context\]\[namespace\]\[object\].

The object will be yellow if it's a pod, blue if it's a node.
