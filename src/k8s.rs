use std::fmt::Debug;

use bytes::Bytes;
use k8s_openapi::{http, List, ListableResource};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity, Url};
use serde::Deserialize;
use url::Host;
use yasna::models::ObjectIdentifier;

use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::{AuthProvider, ExecAuth, ExecProvider};

pub enum UserAuth {
    AuthProvider(Box<AuthProvider>),
    ExecProvider(ExecProvider),
    Ident(Identity),
    Token(String),
    UserPass(String, String),
    //KeyCert(PathBuf, PathBuf),
}

impl UserAuth {
    pub fn _from_identity(id: Identity) -> UserAuth {
        UserAuth::Ident(id)
    }

    pub fn with_auth_provider(auth_provider: AuthProvider) -> UserAuth {
        UserAuth::AuthProvider(Box::new(auth_provider))
    }

    pub fn with_exec_provider(exec_provider: ExecProvider) -> UserAuth {
        UserAuth::ExecProvider(exec_provider)
    }

    pub fn with_token(token: String) -> UserAuth {
        UserAuth::Token(token)
    }

    pub fn with_user_pass(user: String, pass: String) -> UserAuth {
        UserAuth::UserPass(user, pass)
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
        let pkcs12 = Context::use_pkcs12(endpoint);
        let id = get_id_from_paths(key_buf, cert_buf, pkcs12);
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

// fn get_id_pem(keycert: Vec<u8>, cert: PathBuf) -> Identity {
//     let mut buf = Vec::new();
//     File::open(key).unwrap().read_to_end(&mut buf).unwrap();
//     File::open(cert).unwrap().read_to_end(&mut buf).unwrap();
//     Identity::from_pem(&buf).unwrap()
// }

// get the right kind of id
fn get_id_from_pkcs12(key: Vec<u8>, cert: Vec<u8>) -> Identity {
    let key_pem = pem::parse(&key).unwrap();

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

    let cert_pem = pem::parse(&cert).unwrap();

    let pfx = p12::PFX::new(&cert_pem.contents, &key_der, None, "", "").unwrap();

    let pkcs12der = pfx.to_der();

    Identity::from_pkcs12_der(&pkcs12der, "").unwrap()
}

fn get_id_from_paths(key: PathBuf, cert: PathBuf, pkcs12: bool) -> Identity {
    if pkcs12 {
        let mut key_buf = Vec::new();
        File::open(key).unwrap().read_to_end(&mut key_buf).unwrap();

        let mut cert_buf = Vec::new();
        File::open(cert)
            .unwrap()
            .read_to_end(&mut cert_buf)
            .unwrap();
        get_id_from_pkcs12(key_buf, cert_buf)
    } else {
        let mut buf = Vec::new();
        File::open(key).unwrap().read_to_end(&mut buf).unwrap();
        File::open(cert).unwrap().read_to_end(&mut buf).unwrap();
        Identity::from_pem(&buf).unwrap()
    }
}

fn get_id_from_data(key: String, cert: String, pkcs12: bool) -> Identity {
    if pkcs12 {
        get_id_from_pkcs12(key.into_bytes(), cert.into_bytes())
    } else {
        let mut buf = key.into_bytes();
        buf.append(&mut cert.into_bytes());
        Identity::from_pem(&buf).unwrap()
    }
}

pub struct Context {
    pub name: String,
    endpoint: Url,
    client: RefCell<Client>,
    root_ca: Option<Certificate>,
    auth: RefCell<Option<UserAuth>>,
    connect_timeout_secs: u32,
    read_timeout_secs: u32,
}

impl Context {
    pub fn new<S: Into<String>>(
        name: S,
        endpoint: Url,
        root_ca: Option<Certificate>,
        auth: Option<UserAuth>,
        connect_timeout_secs: u32,
        read_timeout_secs: u32,
    ) -> Context {
        let (client, auth) = Context::get_client(
            &endpoint,
            root_ca.clone(),
            auth,
            None,
            connect_timeout_secs,
            read_timeout_secs,
        );
        let client = RefCell::new(client);
        let auth = RefCell::new(auth);
        Context {
            name: name.into(),
            endpoint,
            client,
            root_ca,
            auth,
            connect_timeout_secs,
            read_timeout_secs,
        }
    }

    fn get_client(
        endpoint: &Url,
        root_ca: Option<Certificate>,
        auth: Option<UserAuth>,
        id: Option<Identity>,
        connect_timeout_secs: u32,
        read_timeout_secs: u32,
    ) -> (Client, Option<UserAuth>) {
        let host = endpoint.host().unwrap();
        let client = match host {
            Host::Domain(_) => Client::builder().use_rustls_tls(),
            _ => Client::builder().use_native_tls(),
        };
        let client = match root_ca {
            Some(ca) => client.add_root_certificate(ca),
            None => client,
        };
        let (client, auth) = match auth {
            Some(auth_inner) => match auth_inner {
                UserAuth::Ident(id) => (client.identity(id), None),
                _ => (client, Some(auth_inner)),
            },
            None => (client, auth),
        };
        let client = match id {
            Some(id) => client.identity(id),
            None => client,
        };
        (
            client
                .connect_timeout(Duration::new(connect_timeout_secs.into(), 0))
                .timeout(Duration::new(read_timeout_secs.into(), 0))
                .build()
                .unwrap(),
            auth,
        )
    }

    fn use_pkcs12(endpoint: &Url) -> bool {
        let host = endpoint.host().unwrap();
        match host {
            Host::Domain(_) => false,
            _ => true,
        }
    }

    fn handle_exec_provider(&self, exec_provider: &ExecProvider) {
        let (auth, was_expired) = exec_provider.get_auth();
        match auth {
            ExecAuth::Token(_) => {} // handled below
            ExecAuth::ClientCertKey {
                cert_data,
                key_data,
                ..
            } => {
                if was_expired {
                    let pkcs12 = Context::use_pkcs12(&self.endpoint);
                    let id = get_id_from_data(key_data, cert_data, pkcs12);
                    let auth = self.auth.take();
                    let (new_client, new_auth) = Context::get_client(
                        &self.endpoint,
                        self.root_ca.clone(),
                        auth,
                        Some(id),
                        self.connect_timeout_secs,
                        self.read_timeout_secs,
                    );
                    *self.client.borrow_mut() = new_client;
                    *self.auth.borrow_mut() = new_auth;
                }
            }
        }
    }

    pub fn execute(
        &self,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Bytes>, Box<dyn std::error::Error>> {
        let (parts, body) = k8sreq.into_parts();

        let url = self.endpoint.join(&parts.uri.to_string())?;

        if let Some(UserAuth::ExecProvider(ref exec_provider)) = *self.auth.borrow() {
            self.handle_exec_provider(exec_provider);
        }

        let req = match parts.method {
            http::method::Method::GET => self.client.borrow().get(url),
            http::method::Method::POST => self.client.borrow().post(url),
            _ => unimplemented!(),
        };

        let req = req.body(body);
        let req = match &*self.auth.borrow() {
            Some(auth) => match auth {
                UserAuth::AuthProvider(provider) => match provider.ensure_token() {
                    Some(token) => req.bearer_auth(token),
                    None => {
                        crate::kube::print_token_err();
                        req
                    }
                },
                UserAuth::ExecProvider(ref exec_provider) => {
                    let (auth, _) = exec_provider.get_auth();
                    match auth {
                        ExecAuth::Token(token) => req.bearer_auth(token),
                        ExecAuth::ClientCertKey { .. } => req, // handled above
                    }
                }
                UserAuth::Token(token) => req.bearer_auth(token),
                UserAuth::UserPass(user, pass) => req.basic_auth(user, Some(pass)),
                _ => req,
            },
            None => req,
        };
        let resp = req.send()?;
        let bytes = resp.bytes()?;

        Ok(http::response::Builder::new()
            .status(200)
            .body(bytes)
            .unwrap())
    }

    pub fn read<T: k8s_openapi::Response + Debug>(
        &self,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let response = self.execute(k8sreq)?;
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
        let response = self.execute(k8sreq)?;
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
