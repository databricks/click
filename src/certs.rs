// Copyright 2017 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rustls::{Certificate, PrivateKey};
use rustls::sign::RSASigner;

use std::fs::{File, metadata};
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::Command;

fn need_update(outpath: &Path, inpath: &Path) -> bool {
    if !outpath.exists() {
        return true;
    }
    let out_metadata_res = metadata(&outpath);
    let in_metadata_res = metadata(&inpath);
    if let (Ok(out_metadata), Ok(in_metadata)) = (out_metadata_res, in_metadata_res) {
        if let (Ok(out_mtime), Ok(in_mtime)) = (out_metadata.modified(), in_metadata.modified()) {
            return out_mtime < in_mtime
        }
    }
    false
}

// might need to convert to der format
pub fn get_cert(path: &str) -> Option<Certificate> {
    let inpath = Path::new(path);
    let read_path =
        if inpath.extension().unwrap() != "der" {
            // assume it's not a der, try and convert
            let parent = inpath.parent().unwrap();
            let filename = inpath.file_name().unwrap();
            let outpath = parent.join(format!("{}.der", filename.to_str().unwrap()));
            if need_update(&outpath, inpath) {
                println!("Converting {} to der", inpath.to_str().unwrap());
                Command::new("openssl")
                    .arg("x509")
                    .arg("-outform")
                    .arg("der")
                    .arg("-in")
                    .arg(inpath)
                    .arg("-out")
                    .arg(&outpath)
                    .status().expect("Couldn't convert certificate to der");
            }
            outpath
        } else {
            inpath.to_path_buf()
        };

    let cert_file = File::open(read_path).unwrap();
    let mut cert_br = BufReader::new(cert_file);
    let mut cert_buf = Vec::new();
    cert_br.read_to_end(&mut cert_buf).unwrap();
    Some(Certificate(cert_buf))
}


/// Try and get a private key.  ring only likes things in der format,
/// so we need to convert if things are pems
pub fn get_private_key(path: &str) -> Option<PrivateKey> {
    get_private_key_internal(path, true)
}

fn get_private_key_internal(path: &str, try_conv: bool) -> Option<PrivateKey> {
    let key_file = File::open(path).unwrap();
    let mut key_br = BufReader::new(key_file);
    let mut key_buf = Vec::new();
    key_br.read_to_end(&mut key_buf).unwrap();

    let key = PrivateKey(key_buf);

    match RSASigner::new(&key) {
        Ok(_) => Some(key),
        Err(_) => {
            // Here things failed so we try to convert if asked
            if try_conv {
                let inpath = Path::new(path);
                let parent = inpath.parent().unwrap();
                let filename = inpath.file_name().unwrap();
                let outpath = parent.join(format!("{}.der", filename.to_str().unwrap()));
                if need_update(&outpath, inpath) {
                    println!("Converting {} to der", path);
                    Command::new("openssl")
                        .arg("rsa")
                        .arg("-outform")
                        .arg("der")
                        .arg("-in")
                        .arg(path)
                        .arg("-out")
                        .arg(&outpath)
                        .status().expect("Couldn't convert to der");
                }
                get_private_key_internal(outpath.to_str().unwrap(), false)
            } else {
                None
            }
        }
    }
}
