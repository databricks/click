#!/bin/bash

# This script tries to patch webpki to accept SANs with a : in them, as k8s requires this in some
# cases.  This is a hack, but right now we don't really have a better idea

CARGO_DIR="${CARGO_HOME:-$HOME}/.cargo"
WEBPKI_VERSION=${WEBPKI_VERSION:-"0.12.1"}
WEBPKI_DIR=$(find $CARGO_DIR/registry/src/ -name webpki-$WEBPKI_VERSION)

pushd $WEBPKI_DIR

patch -p1 <<EOF
--- a/src/name.rs
+++ b/src/name.rs
@@ -673,7 +673,7 @@
                 }
             },
 
-            Ok(b'a'...b'z') | Ok(b'A'...b'Z') | Ok(b'_') => {
+            Ok(b'a'...b'z') | Ok(b'A'...b'Z') | Ok(b'_') | Ok(b':') => {
                 label_is_all_numeric = false;
                 label_ends_with_hyphen = false;
                 label_length += 1;
EOF

popd
