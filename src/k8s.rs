use std::fmt::Debug;

use bytes::Bytes;
use k8s_openapi::{http, List, ListableResource};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity, Url};
use serde::Deserialize;
use url::Host;
use yasna::models::ObjectIdentifier;

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub enum UserAuth {
    //#[allow(dead_code)]
    Ident(Identity),
    //KeyCert(PathBuf, PathBuf),
}

impl UserAuth {
    pub fn _from_identity(id: Identity) -> UserAuth {
        UserAuth::Ident(id)
    }

    // construct an identity from a key and cert. need the endpoint to deceide which kind of
    // identity to use since rustls wants something different from nativetls, and we use rustls for
    // dns name hosts and native for ip hosts
    pub fn from_key_cert<P>(key: P, cert: P, endpoint: &Url) -> UserAuth
    where
        PathBuf: From<P>,
    {
        let key_buf = PathBuf::from(key);
        let cert_buf = PathBuf::from(cert);
        let host = endpoint.host().unwrap();
        let using_native = match host {
            Host::Domain(_) => false,
            _ => true,
        };
        let id = get_id(key_buf, cert_buf, using_native);
        UserAuth::Ident(id)
    }
}

// convert a pkcs1 der to pkcs8 format
fn pkcs1to8(pkcs1: &[u8]) -> Vec<u8> {
    let oid = ObjectIdentifier::from_slice(&[1, 2, 840, 113_549, 1, 1, 1]);
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u32(0);
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid);
                writer.next().write_null();
            });
            writer.next().write_bytes(pkcs1);
        })
    })
}

fn get_id_pem(key: PathBuf, cert: PathBuf) -> Identity {
    let mut buf = Vec::new();
    File::open(key).unwrap().read_to_end(&mut buf).unwrap();
    File::open(cert).unwrap().read_to_end(&mut buf).unwrap();
    Identity::from_pem(&buf).unwrap()
}

// get the right kind of id
fn get_id(key: PathBuf, cert: PathBuf, pkcs12: bool) -> Identity {
    if pkcs12 {
        let mut key_buf = Vec::new();
        File::open(key).unwrap().read_to_end(&mut key_buf).unwrap();
        let key_pem = pem::parse(&key_buf).unwrap();

        let key_der = match key_pem.tag.as_str() {
            "RSA PRIVATE KEY" => {
                // pkcs#1 pem, need to convert to pkcs#8
                pkcs1to8(&key_pem.contents)
            }
            "PRIVATE KEY" => {
                // pkcs#8 pem, use as is
                key_pem.contents
            }
            _ => {
                panic!("Unknown key type: {}", key_pem.tag);
            }
        };

        let mut cert_buf = Vec::new();
        File::open(cert)
            .unwrap()
            .read_to_end(&mut cert_buf)
            .unwrap();
        let cert_pem = pem::parse(&cert_buf).unwrap();

        let pfx = p12::PFX::new(&cert_pem.contents, &key_der, None, "", "").unwrap();

        let pkcs12der = pfx.to_der();

        Identity::from_pkcs12_der(&pkcs12der, "").unwrap()
    } else {
        get_id_pem(key, cert)
    }
}

pub struct Context {
    pub name: String,
    endpoint: Url,
    client: Client,
}

impl Context {
    pub fn new<S: Into<String>>(
        name: S,
        endpoint: Url,
        root_ca: Option<Certificate>,
        auth: Option<UserAuth>,
    ) -> Context {
        let host = endpoint.host().unwrap();
        let client = match host {
            Host::Domain(_) => Client::builder().use_rustls_tls(),
            _ => Client::builder().use_native_tls(),
        };
        let client = match root_ca {
            Some(ca) => client.add_root_certificate(ca),
            None => client,
        };
        let client = match auth {
            Some(auth) => match auth {
                UserAuth::Ident(id) => client.identity(id),
            },
            None => client,
        };
        Context {
            name: name.into(),
            endpoint,
            client: client.build().unwrap(),
        }
    }

    pub fn execute(&self, k8sreq: http::Request<Vec<u8>>) -> http::Response<Bytes> {
        let (parts, body) = k8sreq.into_parts();

        let url = self.endpoint.join(&parts.uri.to_string()).unwrap();
        //println!("url is: {}", url);

        let req = match parts.method {
            http::method::Method::GET => self.client.get(url),
            http::method::Method::POST => self.client.post(url),
            _ => unimplemented!(),
        };

        let req = req.body(body);
        let resp = req.send().unwrap();

        http::response::Builder::new()
            .status(200)
            .body(resp.bytes().unwrap())
            .unwrap()
    }

    pub fn read<T: k8s_openapi::Response + Debug>(
        &self,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let response = self.execute(k8sreq);
        let status_code: http::StatusCode = response.status();
        match k8s_openapi::Response::try_from_parts(status_code, response.body()) {
            Ok((res, _)) => Ok(res),
            // Need more response data. We're blocking, so this is a hard error
            Err(k8s_openapi::ResponseError::NeedMoreData) => {
                return Err("failed to read enough data".into())
            }
            // Some other error, like the response body being malformed JSON or invalid UTF-8.
            Err(err) => return Err(format!("error: {} {:?}", status_code, err).into()),
        }
    }

    pub fn execute_list<T: ListableResource + for<'de> Deserialize<'de> + Debug>(
        &self,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<List<T>, Box<dyn std::error::Error>> {
        let response = self.execute(k8sreq);
        let status_code: http::StatusCode = response.status();

        let res_list: List<T> =
            match k8s_openapi::Response::try_from_parts(status_code, response.body()) {
                // Successful response (HTTP 200 and parsed successfully)
                Ok((k8s_openapi::ListResponse::Ok(res_list), _)) => res_list,

                // Some unexpected response
                // (not HTTP 200, but still parsed successfully)
                Ok(other) => {
                    return Err(format!("expected Ok but got {} {:?}", status_code, other).into())
                }

                // Need more response data. We're blocking, so this is a hard error
                Err(k8s_openapi::ResponseError::NeedMoreData) => {
                    return Err("failed to read enough data".into())
                }

                // Some other error, like the response body being malformed JSON or invalid UTF-8.
                Err(err) => return Err(format!("error: {} {:?}", status_code, err).into()),
            };

        Ok(res_list)
    }
}
