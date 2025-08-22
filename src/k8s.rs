// Copyright 2021 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::engine::{general_purpose::STANDARD, Engine};
use bytes::Bytes;
use k8s_openapi::{http, List, ListableResource};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity, Url};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use url::Host;
use yasna::models::ObjectIdentifier;

use std::cell::RefCell;
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use crate::{
    config::{AuthProvider, ExecAuth, ExecProvider},
    error::{ClickErrNo, ClickError},
};

#[derive(Clone)]
pub enum UserAuth {
    AuthProvider(Box<AuthProvider>),
    ExecProvider(Box<ExecProvider>),
    Ident(Identity),
    Token(String),
    UserPass(String, String),
    //KeyCert(PathBuf, PathBuf),
}

impl UserAuth {
    pub fn _from_identity(id: Identity) -> Result<UserAuth, ClickError> {
        Ok(UserAuth::Ident(id))
    }

    pub fn with_auth_provider(auth_provider: AuthProvider) -> Result<UserAuth, ClickError> {
        Ok(UserAuth::AuthProvider(Box::new(auth_provider)))
    }

    pub fn with_exec_provider(exec_provider: ExecProvider) -> Result<UserAuth, ClickError> {
        Ok(UserAuth::ExecProvider(Box::new(exec_provider)))
    }

    pub fn with_token(token: String) -> Result<UserAuth, ClickError> {
        Ok(UserAuth::Token(token))
    }

    pub fn with_user_pass(user: String, pass: String) -> Result<UserAuth, ClickError> {
        Ok(UserAuth::UserPass(user, pass))
    }

    /// construct an identity from a key and cert. need the endpoint to deceide which kind of
    /// identity to use since rustls wants something different from nativetls, and we use rustls for
    /// dns name hosts and native for ip hosts
    pub fn from_key_cert<P>(key: P, cert: P, endpoint: &Url) -> Result<UserAuth, ClickError>
    where
        PathBuf: From<P>,
    {
        let key_buf = PathBuf::from(key);
        let cert_buf = PathBuf::from(cert);
        let pkcs12 = Context::use_pkcs12(endpoint);
        let id = get_id_from_paths(key_buf, cert_buf, pkcs12)?;
        Ok(UserAuth::Ident(id))
    }

    /// same as above, but use already read data. The data should be base64 encoded pems
    pub fn from_key_cert_data(
        key: String,
        cert: String,
        endpoint: &Url,
    ) -> Result<UserAuth, ClickError> {
        let key_decoded = STANDARD.decode(key)?;
        let cert_decoded = STANDARD.decode(cert)?;
        let pkcs12 = Context::use_pkcs12(endpoint);
        let id = get_id_from_data(key_decoded, cert_decoded, pkcs12)?;
        Ok(UserAuth::Ident(id))
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

// get the right kind of id
fn get_id_from_pkcs12(key: Vec<u8>, cert: Vec<u8>) -> Result<Identity, ClickError> {
    let key_pem = pem::parse(key)?;

    let key_der = match key_pem.tag() {
        "RSA PRIVATE KEY" => {
            // pkcs#1 pem, need to convert to pkcs#8
            pkcs1to8(key_pem.contents())
        }
        "PRIVATE KEY" => {
            // pkcs#8 pem, use as is
            key_pem.contents().to_vec()
        }
        _ => {
            return Err(ClickError::ConfigFileError(format!(
                "Unknown key type: {}",
                key_pem.tag()
            )));
        }
    };

    let cert_pem = pem::parse(cert)?;

    let pfx = p12::PFX::new(cert_pem.contents(), &key_der, None, "", "")
        .ok_or_else(|| ClickError::ConfigFileError("Could not parse pkcs12 data".to_string()))?;

    let pkcs12der = pfx.to_der();

    Identity::from_pkcs12_der(&pkcs12der, "").map_err(|e| e.into())
}

fn get_id_from_paths(key: PathBuf, cert: PathBuf, pkcs12: bool) -> Result<Identity, ClickError> {
    let mut key_buf = Vec::new();
    File::open(key)?.read_to_end(&mut key_buf)?;
    if pkcs12 {
        let mut cert_buf = Vec::new();
        File::open(cert)?.read_to_end(&mut cert_buf)?;
        get_id_from_pkcs12(key_buf, cert_buf)
    } else {
        // for from_pem key and cert are in same buffer
        File::open(cert)?.read_to_end(&mut key_buf)?;
        Identity::from_pem(&key_buf).map_err(|e| e.into())
    }
}

fn get_id_from_data(
    mut key: Vec<u8>,
    mut cert: Vec<u8>,
    pkcs12: bool,
) -> Result<Identity, ClickError> {
    if pkcs12 {
        get_id_from_pkcs12(key, cert)
    } else {
        key.append(&mut cert);
        Identity::from_pem(&key).map_err(|e| e.into())
    }
}

pub struct Context {
    pub name: String,
    pub endpoint: Url,
    client: RefCell<Client>,
    log_client: RefCell<Client>,
    root_cas: Option<Vec<Certificate>>,
    auth: RefCell<Option<UserAuth>>,
    impersonate_user: Option<String>,
    connect_timeout_secs: u32,
    read_timeout_secs: u32,
    custom_dns_mapping: Option<(String, IpAddr)>,
}

impl Context {
    #[allow(clippy::too_many_arguments)]
    pub fn new<S: Into<String>>(
        name: S,
        endpoint: Url,
        root_cas: Option<Vec<Certificate>>,
        auth: Option<UserAuth>,
        impersonate_user: Option<String>,
        connect_timeout_secs: u32,
        read_timeout_secs: u32,
        custom_dns_mapping: Option<(String, IpAddr)>,
    ) -> Context {
        let (client, client_auth) = Context::get_client(
            &endpoint,
            root_cas.clone(),
            auth.clone(),
            None,
            connect_timeout_secs,
            read_timeout_secs,
            custom_dns_mapping.clone(),
        );
        // have to create a special client for logs until
        // https://github.com/seanmonstar/reqwest/issues/1380
        // is resolved
        let (log_client, _) = Context::get_client(
            &endpoint,
            root_cas.clone(),
            auth,
            None,
            u32::MAX,
            u32::MAX,
            custom_dns_mapping.clone(),
        );
        let client = RefCell::new(client);
        let log_client = RefCell::new(log_client);
        let client_auth = RefCell::new(client_auth);
        Context {
            name: name.into(),
            endpoint,
            client,
            log_client,
            root_cas,
            auth: client_auth,
            impersonate_user,
            connect_timeout_secs,
            read_timeout_secs,
            custom_dns_mapping,
        }
    }

    fn get_client(
        endpoint: &Url,
        root_cas: Option<Vec<Certificate>>,
        auth: Option<UserAuth>,
        id: Option<Identity>,
        connect_timeout_secs: u32,
        read_timeout_secs: u32,
        custom_dns_mapping: Option<(String, IpAddr)>,
    ) -> (Client, Option<UserAuth>) {
        let host = endpoint.host().unwrap();
        let mut client = match host {
            Host::Domain(_) => Client::builder().use_rustls_tls(),
            _ => Client::builder().use_native_tls(),
        };

        // Use custom DNS mapping if we have one
        if let Some((hostname, ip)) = custom_dns_mapping {
            // reqwest's resolve method allows mapping specific hostnames to IP addresses
            client = client.resolve(&hostname, SocketAddr::new(ip, 443));
        }
        let client = match root_cas {
            Some(cas) => {
                let mut client = client;
                for ca in cas.into_iter() {
                    client = client.add_root_certificate(ca);
                }
                client
            }
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
        !matches!(host, Host::Domain(_))
    }

    fn handle_exec_provider(&self, exec_provider: &ExecProvider) -> Option<UserAuth> {
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
                    let id =
                        get_id_from_data(key_data.into_bytes(), cert_data.into_bytes(), pkcs12)
                            .unwrap(); // TODO: Handle error
                    let (new_client, new_auth) = Context::get_client(
                        &self.endpoint,
                        self.root_cas.clone(),
                        self.auth.clone().take(),
                        Some(id.clone()),
                        self.connect_timeout_secs,
                        self.read_timeout_secs,
                        self.custom_dns_mapping.clone(),
                    );
                    let (new_log_client, _) = Context::get_client(
                        &self.endpoint,
                        self.root_cas.clone(),
                        self.auth.clone().take(),
                        Some(id),
                        u32::MAX,
                        u32::MAX,
                        self.custom_dns_mapping.clone(),
                    );
                    *self.client.borrow_mut() = new_client;
                    *self.log_client.borrow_mut() = new_log_client;
                    return new_auth;
                }
            }
        }
        None
    }

    pub fn execute(
        &self,
        impersonate_user: Option<&str>,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Bytes>, ClickError> {
        let (parts, body) = k8sreq.into_parts();

        let url = self.endpoint.join(&parts.uri.to_string())?;

        let new_provider = {
            // TODO: Fix this mess
            if let Some(UserAuth::ExecProvider(ref exec_provider)) = *self.auth.borrow() {
                self.handle_exec_provider(exec_provider)
            } else {
                None
            }
        };
        if let Some(new_provider) = new_provider {
            self.auth.borrow_mut().replace(new_provider);
        }

        let req = match parts.method {
            http::method::Method::GET => self.client.borrow().get(url),
            http::method::Method::POST => self.client.borrow().post(url),
            http::method::Method::DELETE => self.client.borrow().delete(url),
            _ => unimplemented!(),
        };

        let req = if let Some(user) = impersonate_user {
            req.header("Impersonate-User", user)
        } else if let Some(user) = self.impersonate_user.as_ref() {
            req.header("Impersonate-User", user)
        } else {
            req
        };

        let req = req.headers(parts.headers).body(body);
        let req = match &*self.auth.borrow() {
            Some(auth) => match auth {
                UserAuth::AuthProvider(provider) => {
                    let token = provider.get_token()?;
                    req.bearer_auth(token)
                }
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
        let stat = resp.status();
        let bytes = resp.bytes()?;

        Ok(http::response::Builder::new()
            .status(stat)
            .body(bytes)
            .unwrap())
    }

    // execute a request and return the reqwest response. this implements io::Read so it can be used
    // for streaming operations like logs
    pub fn execute_reader(
        &self,
        impersonate_user: Option<&str>,
        k8sreq: http::Request<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<reqwest::blocking::Response, ClickError> {
        let (parts, body) = k8sreq.into_parts();

        let url = self.endpoint.join(&parts.uri.to_string())?;

        if let Some(UserAuth::ExecProvider(ref exec_provider)) = *self.auth.borrow() {
            self.handle_exec_provider(exec_provider);
        }

        let req = match parts.method {
            http::method::Method::GET => self.log_client.borrow().get(url),
            http::method::Method::POST => self.log_client.borrow().post(url),
            http::method::Method::DELETE => self.log_client.borrow().delete(url),
            _ => unimplemented!(),
        };

        let req = if let Some(user) = impersonate_user {
            req.header("Impersonate-User", user)
        } else if let Some(user) = self.impersonate_user.as_ref() {
            req.header("Impersonate-User", user)
        } else {
            req
        };

        let req = req.body(body);
        let req = match &*self.auth.borrow() {
            Some(auth) => match auth {
                UserAuth::AuthProvider(provider) => {
                    let token = provider.get_token()?;
                    req.bearer_auth(token)
                }
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

        let req = match timeout {
            Some(timeout) => req.timeout(timeout),
            None => req, // log_client above already has a super long timeout
        };

        let resp = req.send()?;

        if resp.status().is_success() {
            Ok(resp)
        } else {
            let err = match resp.error_for_status_ref() {
                Ok(_) => panic!("status was not success, but error_for_status returned Ok"),
                Err(e) => e,
            };
            let body = resp.json()?;
            Err(ClickError::Reqwest(err, Some(body)))
        }
    }

    pub fn read<T: k8s_openapi::Response + Debug>(
        &self,
        impersonate_user: Option<&str>,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<T, ClickError> {
        let response = self.execute(impersonate_user, k8sreq)?;
        let status_code: http::StatusCode = response.status();
        match k8s_openapi::Response::try_from_parts(status_code, response.body()) {
            Ok((res, _)) => Ok(res),
            // Need more response data. We're blocking, so this is a hard error
            Err(e) => Err(ClickError::ResponseError(e)),
        }
    }

    pub fn execute_list<T: ListableResource + for<'de> Deserialize<'de> + Debug>(
        &self,
        impersonate_user: Option<&str>,
        k8sreq: http::Request<Vec<u8>>,
    ) -> Result<List<T>, ClickError> {
        let response = self.execute(impersonate_user, k8sreq)?;
        let status_code: http::StatusCode = response.status();

        let res_list: List<T> =
            match k8s_openapi::Response::try_from_parts(status_code, response.body()) {
                // Successful response (HTTP 200 and parsed successfully)
                Ok((k8s_openapi::ListResponse::Ok(res_list), _)) => res_list,

                // Some unexpected response
                // (not HTTP 200, but still parsed successfully)
                Ok(other) => {
                    if status_code == http::StatusCode::UNAUTHORIZED {
                        return Err(ClickError::Kube(ClickErrNo::Unauthorized));
                    } else {
                        return Err(ClickError::ParseErr(
                            // TODO maybe a special error type for this
                            format!("Got unexpected status {status_code} {other:?}"),
                        ));
                    }
                }
                Err(e) => return Err(ClickError::ResponseError(e)),
            };

        Ok(res_list)
    }
}
