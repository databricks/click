# Click

Click is the Command Line Interactive Controller for Kubernetes.  It's
goal is to make managing a large number of Kubernetes clusters/objects
quick and efficient.

![A demo gif that shows a few features](https://imgur.com/ft4WHcL.gif)

# Usage Model
Click is a REPL.  When running there is a current active config which
includes the current Kubernetes context, and optionally a namespace
and Kubernetes object.  Commands are then applied to the active config
so it's not necessary to keep specifying what objects to target.

# Installing / Building
You'll need rust and cargo.  See
[here](https://doc.rust-lang.org/cargo/getting-started/installation.html) for instructions on how to
get them.

Click is on crates.io, so you can just run `cargo install` to install it.

Alternately, to build it yourself, clone the click repository and run `cargo build`.

# Running
If you used `cargo install`, you can just run `click` (assuming `~/.cargo/bin` is in your PATH).

If you built from source, run `./target/debug/click`.  It's not recommended to use `cargo run`
as that messes with Ctrl-C handling. (see:
https://github.com/rust-lang-nursery/rustup.rs/issues/806)

Click looks in ~/.kube/config by default for you Kubernetes
configuration.  It also stores its own config in the .kube dir.  You
can change this with the --config option.

Once you're in the REPL, try typing `help` to see what you can do.

# Prompt
The order of the prompt is \[context\]\[namespace\]\[object\].

The object changes color depending on what type of object it is.  (e.g yellow for pods, blue for
nodes and so on)

# Why am I getting a BadDER error
If your Kubernetes cluster is using Node Authorization
(https://kubernetes.io/docs/admin/authorization/node/) your API Server may be using a certificate
with a DNS name like "system:something".  This is technically a bad cert as DNS names can't have a
colon in them, and since the WebPKI crate is more strict than Go, Click will not accept the cert
from the API Server even though kubectl will.  

For the moment, you can build click, then run the `fix_bad_der.sh` script that's in the util
directory, and then run `cargo clean`, and then rebuild click.  This patches WebPKI to accept the
cert.
