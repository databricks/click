# Click

Click is the Command Line Interactive Contoller for Kubernetes.  It's
goal is to make managing a large number of kubernetes clusters/objects
quick and efficient.

![A demo gif that shows a few features](https://imgur.com/ft4WHcL.gif)

# Usage Model
Click is a REPL.  When running there is a current active config which
includes the current kubernetes context, and optionally a namespace
and kubernetes object.  Commands are then applied to the active config
so it's not necessary to keep specifying what objects to target.

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

# Why am I getting BadDER error
If your Kubernetes cluster is using Node Authorization
(https://kubernetes.io/docs/admin/authorization/node/) your API Server may be using a certificate
with a DNS name like "system:something".  This is technically a bad cert as DNS names can't have a
colon in them, and since the WebPKI crate is more strict than Go, Click will not accept the cert
from the API Server even though kubectl will.  

For the moment, you can build click, then run the `fix_bad_der.sh` script that's in the util
directory, and then rebuild click.  This patches WebPKI to accept the cert.
