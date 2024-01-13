# Click
-----
Click is the Command Line Interactive Controller for Kubernetes.
Its purpose is to manage a large number of Kubernetes clusters/objects quickly and efficiently.

## Code Status
![Master Status](https://github.com/databricks/click/actions/workflows/push-actions.yml/badge.svg?branch=master)

## CHANGELOG
See the [CHANGELOG](CHANGELOG.md) for a release history.


## Demo Screencast
![A demo gif that shows a few features](https://imgur.com/ft4WHcL.gif)

# Usage Model
Click is a REPL. When running Click, there is a current active config which
includes the current Kubernetes context, and optionally a namespace
and Kubernetes object. Commands are then applied to the active config
so it's not necessary to keep specifying what objects to target.

# Installing
You'll need rust and cargo. See
[here](https://doc.rust-lang.org/cargo/getting-started/installation.html) for instructions on how to
get them.

Click is on crates.io, so you can just run `cargo install click` to install it.

Alternatively, to build it yourself, clone the click repository and run `cargo build`.

## Arch Linux

There is an [aur](https://aur.archlinux.org/packages/click/) available.

## Docker build

`docker build . -t click`

# Running
If you used `cargo install`, you can just run `click` (assuming `~/.cargo/bin` is in your PATH).

If you built from source, run `./target/debug/click`, or do `cargo run`.

Click looks in ~/.kube/config by default for your Kubernetes
configuration. It also stores its own config in the .kube dir. You
can change this with the --config option. If `KUBECONFIG` is set, it will use any files found there
as the kubernetes config files.

Once you're in the REPL, type `help` to see what you can do.

## Docker

`docker run --rm -it -v $HOME/.kube/:/root/.kube/ click`

# Prompt
The order of the prompt is \[context\]\[namespace\]\[object\].

The object changes color depending on what type of object it is. (e.g yellow for pods, blue for
nodes and so on)

# Supported Authentication
Click currently supports the following ways of authenticating to a Kubernetes clusters:

* token
* username / password
* private key / certificate
* gke style authentication provider

## GKE Support
For Google Kubernetes Engine, Click supports reading the token already in the kube config file.  If
that token has expired, Click will request a new token and use that. It does not save the new token
back into the config file (yet).

## Why am I getting a BadDER error
If your Kubernetes cluster is using Node Authorization
(https://kubernetes.io/docs/admin/authorization/node/) your API Server may be using a certificate
with a DNS name like "system:something".  This is technically a bad cert as DNS names can't have a
colon in them. Since the WebPKI crate is more strict than Go, Click will not accept the cert
from the API Server even though kubectl will.

To temporarily patch WebPKI to accept the cert:
1. Build Click
2. Run the `fix_bad_der.sh` script that is in the util directory
3. Run `cargo clean`
4. Rebuild Click
