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

use subjaltnames::{get_subj_alt_names, SubjAltName};

use der_parser;
use regex::Regex;
use rustls::{ClientConfig, ClientSession, Session};
use rustls::{Certificate, PrivateKey};
use rustls::sign::RSASigner;
use untrusted::{Input, Reader};

use std::error::Error;
use std::fs::File;
use std::net::{IpAddr, TcpStream};
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::sync::Arc;

// might need to convert to der format
pub fn get_cert(path: &str) -> Option<Certificate> {
    let inpath = Path::new(path);
    let cert_file = File::open(inpath).unwrap();
    if inpath.extension().unwrap() == "der" {
        // with .der, just read and return
        let mut cert_br = BufReader::new(cert_file);
        let mut cert_buf = Vec::new();
        cert_br.read_to_end(&mut cert_buf).unwrap();
        Some(Certificate(cert_buf))
    } else {
        // assume it's not a der and is a pem and try and convert
        let mut pem_br = BufReader::new(cert_file);
        let mut pem_buf = String::new();
        match pem_br.read_to_string(&mut pem_buf) {
            Ok(_) => get_cert_from_pem(pem_buf.as_str()),
            Err(e) => {
                println!("Error reading cert {}: {}", path, e);
                None
            }
        }
    }
}

/// Try and get a private key.  ring only likes things in der format,
/// so we need to convert if things are pems
pub fn get_private_key(path: &str) -> Option<PrivateKey> {
    let key_file = File::open(path).unwrap();
    let mut key_br = BufReader::new(key_file);
    let mut key_buf = Vec::new();
    key_br.read_to_end(&mut key_buf).unwrap();

    let key = PrivateKey(key_buf.clone());

    match RSASigner::new(&key) {
        Ok(_) => Some(key), // it worked, just return it
        Err(_) => {
            // failed, so try and convert
            key_buf.retain(|&i| i != 0);
            get_key_from_str(String::from_utf8(key_buf).unwrap().as_str())
        }
    }
}

fn get_body(s: &str) -> Option<String> {
    lazy_static! {
        // regex taken from pem-parser crate: https://github.com/yberreby/pem-parser-rs
        static ref RE: Regex = Regex::new(r"(-----BEGIN .*-----\n)((?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\n)+)(-----END .*-----)").unwrap();
    }
    let remove_carriage = s.replace("\r", "");
    match RE.captures(remove_carriage.as_str()) {
        Some(caps) => caps.get(2).map(|m| {
            let no_headers = m.as_str();
            no_headers.replace("\n", "")
        }),
        None => None,
    }
}

/// Check if string is a pkcs#8 private key.  These start with the RE defined below.
fn is_pkcs8(s: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap();
    }
    RE.is_match(s)
}

/// Make sure the key is valid, to avoid panics when trying to use it
fn validate_private_key(key: PrivateKey) -> Option<PrivateKey> {
    match RSASigner::new(&key) {
        Ok(_) => Some(key),
        Err(e) => {
            println!("Private key data was invalid: {:?}", e);
            None
        }
    }
}

// Convert pem string to der cert
pub fn get_cert_from_pem(pem: &str) -> Option<Certificate> {
    match get_body(pem) {
        Some(body) => match ::base64::decode(body.as_str()) {
            Ok(der_vec) => Some(Certificate(der_vec)),
            Err(e) => {
                println!("Failed to decode cert: {}", e.description());
                None
            }
        },
        None => None,
    }
}

static RSAOID: &'static [u64] = &[1, 2, 840, 113549, 1, 1, 1];
// Convert rsa/pkcs8 private string to der cert
pub fn get_key_from_str(s: &str) -> Option<PrivateKey> {
    let pkcs8 = is_pkcs8(s);
    match get_body(s) {
        Some(body) => {
            match ::base64::decode(body.as_str()) {
                Ok(der_vec) => {
                    if pkcs8 {
                        // need to strip out extra info from pkcs8 and get
                        // just private key bitstring
                        let der = der_parser::parse_der(der_vec.as_slice()).unwrap().1;
                        let mut di = der.ref_iter();
                        di.next(); // skip version
                        let algo = di.next();
                        let bitso = di.next();
                        match (algo, bitso) {
                            (Some(alg), Some(bits)) => match alg.ref_iter().next() {
                                Some(oid) => {
                                    if let der_parser::DerObjectContent::OID(ref v) = oid.content {
                                        if v == &RSAOID {
                                            if let der_parser::DerObjectContent::OctetString(
                                                ref v,
                                            ) = bits.content
                                            {
                                                validate_private_key(PrivateKey(v.to_vec()))
                                            } else {
                                                println!("Bit string for private key is invalid");
                                                None
                                            }
                                        } else {
                                            println!("Invalid OID in pkcs8 key, cannot continue");
                                            None
                                        }
                                    } else {
                                        println!("Invalid OID in pkcs8 key, cannot continue");
                                        None
                                    }
                                }
                                None => {
                                    println!("pkcs8 does not have an OID, cannot continue");
                                    None
                                }
                            },
                            _ => {
                                println!("Invalid der data in pkcs8 private key, cannot continue");
                                None
                            }
                        }
                    } else {
                        validate_private_key(PrivateKey(der_vec))
                    }
                }
                Err(e) => {
                    println!("Failed to decode private key: {:?}", e);
                    None
                }
            }
        }
        None => None,
    }
}

fn fetch_cert_for_ip(ip: &IpAddr, port: u16) -> Result<Vec<Certificate>, io::Error> {
    let config = ClientConfig::new();
    let ac = Arc::new(config);
    let mut session = ClientSession::new(&ac, format!("{}:{}", ip, port).as_str());
    let mut sock = TcpStream::connect((*ip, port))?;
    session.write_tls(&mut sock)?;
    let rc = session.read_tls(&mut sock)?;

    // If we're ready but there's no data: EOF.
    if rc == 0 {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "No data to read"));
    }
    let _processed = session.process_new_packets();
    Ok(session.get_peer_certificates().unwrap_or(Vec::new()))
}

// Fetch the cert from the specified endpoint, then, if cert contains a SAN that matches target_ip,
// and a dns SAN, return the dns SAN.  This is a *HACK*.  But webpki does not support IP Address
// SANS, and that's what minikube uses, so without this we can't talk to mikikube clusters.  This is
// essentially safe, as it's just saying, hey, if the .kube/config is pointing at an IP address, try
// and find a hostname we can use instead.  We do require that the specified IP is in the cert, so
// it won't enable connecting just anywhere.  The DNS override to make this work is done in
// connector.rs.
pub fn try_ip_to_name(target_ip: &IpAddr, port: u16) -> Option<String> {
    fetch_cert_for_ip(target_ip, port)
        .map(|certs| {
            for cert in certs.iter() {
                let mut reader = Reader::new(Input::from(cert.0.as_slice()));
                let names = get_subj_alt_names(&mut reader);
                let mut dns_name: Option<String> = None;
                let mut found = false;
                for san in names.into_iter() {
                    match san {
                        SubjAltName::DNSName(dns) => dns_name = Some(String::from(dns)),
                        SubjAltName::IPAddress(ip) => {
                            let ipaddr = IpAddr::from(ip);
                            if &ipaddr == target_ip {
                                found = true;
                            }
                        }
                    }
                }
                if found {
                    return dns_name;
                }
            }
            None
        })
        .ok()
        .and_then(|res| res)
}
