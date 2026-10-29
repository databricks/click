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
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

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

// Helper function to create custom DNS mapping from server URL and TLS server name
// This is called lazily when the client is created
fn create_custom_dns_mapping(server_url: &str, tls_server_name: &str) -> Option<(String, IpAddr)> {
    let url = reqwest::Url::parse(server_url).ok()?;
    let proxy_host = url.host_str()?;

    // Resolve the proxy host to its IP address using the system resolver
    let proxy_ip = (proxy_host, 0u16).to_socket_addrs().ok()?.next()?.ip();

    Some((tls_server_name.to_string(), proxy_ip))
}

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

    /// construct an identity from a key and cert using PEM format
    pub fn from_key_cert<P>(key: P, cert: P) -> Result<UserAuth, ClickError>
    where
        PathBuf: From<P>,
    {
        let key_buf = PathBuf::from(key);
        let cert_buf = PathBuf::from(cert);
        let id = get_id_from_paths(key_buf, cert_buf)?;
        Ok(UserAuth::Ident(id))
    }

    /// same as above, but use already read data. The data should be base64 encoded pems
    pub fn from_key_cert_data(key: String, cert: String) -> Result<UserAuth, ClickError> {
        let key_decoded = STANDARD.decode(key)?;
        let cert_decoded = STANDARD.decode(cert)?;
        let id = get_id_from_data(key_decoded, cert_decoded)?;
        Ok(UserAuth::Ident(id))
    }
}

fn get_id_from_paths(key: PathBuf, cert: PathBuf) -> Result<Identity, ClickError> {
    let mut key_buf = Vec::new();
    File::open(key)?.read_to_end(&mut key_buf)?;
    // for from_pem key and cert are in same buffer
    File::open(cert)?.read_to_end(&mut key_buf)?;
    Identity::from_pem(&key_buf).map_err(|e| e.into())
}

fn get_id_from_data(mut key: Vec<u8>, mut cert: Vec<u8>) -> Result<Identity, ClickError> {
    key.append(&mut cert);
    Identity::from_pem(&key).map_err(|e| e.into())
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
    server_url: String,
    tls_server_name: Option<String>,
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
        server_url: String,
        tls_server_name: Option<String>,
    ) -> Context {
        let (client, client_auth) = Context::get_client(
            root_cas.clone(),
            auth.clone(),
            None,
            connect_timeout_secs,
            read_timeout_secs,
            &server_url,
            &tls_server_name,
        );
        // have to create a special client for logs until
        // https://github.com/seanmonstar/reqwest/issues/1380
        // is resolved
        let (log_client, _) = Context::get_client(
            root_cas.clone(),
            auth,
            None,
            u32::MAX,
            u32::MAX,
            &server_url,
            &tls_server_name,
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
            server_url,
            tls_server_name,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn get_client(
        root_cas: Option<Vec<Certificate>>,
        auth: Option<UserAuth>,
        id: Option<Identity>,
        connect_timeout_secs: u32,
        read_timeout_secs: u32,
        server_url: &str,
        tls_server_name: &Option<String>,
    ) -> (Client, Option<UserAuth>) {
        let mut client = Client::builder().use_rustls_tls();

        // Create custom DNS mapping if we have a TLS server name
        if let Some(tls_name) = tls_server_name {
            if let Some((hostname, ip)) = create_custom_dns_mapping(server_url, tls_name) {
                // reqwest's resolve method allows mapping specific hostnames to IP addresses
                client = client.resolve(&hostname, SocketAddr::new(ip, 443));
            }
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
                    let id =
                        get_id_from_data(key_data.into_bytes(), cert_data.into_bytes()).unwrap(); // TODO: Handle error
                    let (new_client, new_auth) = Context::get_client(
                        self.root_cas.clone(),
                        self.auth.clone().take(),
                        Some(id.clone()),
                        self.connect_timeout_secs,
                        self.read_timeout_secs,
                        &self.server_url,
                        &self.tls_server_name,
                    );
                    let (new_log_client, _) = Context::get_client(
                        self.root_cas.clone(),
                        self.auth.clone().take(),
                        Some(id),
                        u32::MAX,
                        u32::MAX,
                        &self.server_url,
                        &self.tls_server_name,
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

        let req = parts.headers.iter().fold(req, |req, (name, value)| {
            req.header(name.as_str(), value.as_bytes())
        });
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
        let resp = req.send()?;
        let stat = resp.status();
        let bytes = resp.bytes()?;

        Ok(http::response::Builder::new()
            .status(stat.as_u16())
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
