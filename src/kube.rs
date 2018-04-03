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

//! Dealing with various kubernetes api calls

use ansi_term::Colour::{Green, Red, Yellow};
use chrono::DateTime;
use chrono::offset::Utc;
use hyper::{Client, Url};
use hyper::client::{Body, RequestBuilder};
use hyper::client::request::Request;
use hyper::client::response::Response;
use hyper::header::{Authorization, Basic, Bearer};
use hyper::method::Method;
use hyper::status::StatusCode;
use hyper_rustls::TlsClient;
use serde::Deserialize;
use serde_json;
use serde_json::{Map, Value};
use rustls::{self, Certificate, PrivateKey};

use std::fmt;
use std::io::BufReader;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use config::AuthProvider;
use connector::ClickSslConnector;
use error::{KubeErrNo, KubeError};

// Various things we can return from the kubernetes api

// objects

#[derive(Debug, Deserialize)]
pub struct OwnerReference {
    pub controller: bool,
    pub kind: String,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub namespace: Option<String>,
    #[serde(rename = "creationTimestamp")] pub creation_timestamp: Option<DateTime<Utc>>,
    #[serde(rename = "deletionTimestamp")] pub deletion_timestamp: Option<DateTime<Utc>>,
    pub labels: Option<Map<String, Value>>,
    pub annotations: Option<Map<String, Value>>,
    #[serde(rename = "ownerReferences")] pub owner_refs: Option<Vec<OwnerReference>>,
}

// pods

#[derive(Debug, Deserialize)]
pub enum ContainerState {
    #[serde(rename = "running")]
    Running {
        #[serde(rename = "startedAt")] started_at: Option<DateTime<Utc>>,
    },
    #[serde(rename = "terminated")]
    Terminated {
        #[serde(rename = "containerId")] container_id: Option<String>,
        #[serde(rename = "exitCode")] exit_code: u32,
        #[serde(rename = "finishedAt")] finished_at: Option<DateTime<Utc>>,
        message: Option<String>,
        reason: Option<String>,
        signal: Option<u32>,
        #[serde(rename = "startedAt")] started_at: Option<DateTime<Utc>>,
    },
    #[serde(rename = "waiting")]
    Waiting {
        message: Option<String>,
        reason: Option<String>,
    },
}

impl fmt::Display for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ContainerState::Running { started_at } => match started_at {
                Some(sa) => write!(f, "{} (started: {})", Green.paint("running"), sa),
                None => write!(f, "{} (unknown start time)", Green.paint("running")),
            },
            &ContainerState::Terminated {
                container_id: _,
                ref exit_code,
                ref finished_at,
                message: _,
                reason: _,
                signal: _,
                started_at: _,
            } => match finished_at {
                &Some(fa) => write!(
                    f,
                    "{} at {} (exit code: {})",
                    Red.paint("terminated"),
                    fa,
                    exit_code
                ),
                &None => write!(
                    f,
                    "{} (time unknown) (exit code: {})",
                    Red.paint("terminated"),
                    exit_code
                ),
            },
            &ContainerState::Waiting {
                message: _,
                ref reason,
            } => write!(
                f,
                "{} ({})",
                Yellow.paint("waiting"),
                reason.as_ref().unwrap_or(&"<no reason given>".to_owned())
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ContainerStatus {
    #[serde(rename = "containerID")] pub id: Option<String>,
    pub name: String,
    pub image: String,
    #[serde(rename = "restartCount")] pub restart_count: u32,
    pub ready: bool,
    pub state: ContainerState,
}

#[derive(Debug, Deserialize)]
pub struct PodStatus {
    pub phase: String,
    #[serde(rename = "containerStatuses")] pub container_statuses: Option<Vec<ContainerStatus>>,
}

#[derive(Debug, Deserialize)]
pub struct VolumeMount {
    #[serde(rename = "mountPath")] pub mount_path: String,
    pub name: String,
    #[serde(rename = "readOnly")] pub read_only: Option<bool>,
    #[serde(rename = "subPath")] pub sub_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub args: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    #[serde(rename = "volumeMounts")] pub volume_mounts: Option<Vec<VolumeMount>>,
}

#[derive(Debug, Deserialize)]
pub struct PodSpec {
    pub hostname: Option<String>,
    #[serde(rename = "nodeName")] pub node_name: Option<String>,
    pub containers: Vec<ContainerSpec>,
}

#[derive(Debug, Deserialize)]
pub struct Pod {
    pub metadata: Metadata,
    pub spec: PodSpec,
    pub status: PodStatus,
}

#[derive(Debug, Deserialize)]
pub struct PodList {
    pub items: Vec<Pod>,
}

// Events
#[derive(Debug, Deserialize)]
pub struct Event {
    pub count: u32,
    pub message: String,
    pub reason: String,
    #[serde(rename = "lastTimestamp")] pub last_timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct EventList {
    pub items: Vec<Event>,
}

// Nodes
#[derive(Debug, Deserialize)]
pub struct NodeCondition {
    #[serde(rename = "type")] pub typ: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct NodeStatus {
    pub conditions: Vec<NodeCondition>,
}

#[derive(Debug, Deserialize)]
pub struct NodeSpec {
    pub unschedulable: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Node {
    pub metadata: Metadata,
    pub spec: NodeSpec,
    pub status: NodeStatus,
}

#[derive(Debug, Deserialize)]
pub struct NodeList {
    pub items: Vec<Node>,
}

// Deployments
fn replicas_none() -> u32 {
    0
}

fn replicas_one() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct DeploymentSpec {
    #[serde(default = "replicas_one")] pub replicas: u32,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentStatus {
    #[serde(default = "replicas_none")] pub replicas: u32,
    #[serde(default = "replicas_none", rename = "availableReplicas")] pub available: u32,
    #[serde(default = "replicas_none", rename = "updatedReplicas")] pub updated: u32,
}

#[derive(Debug, Deserialize)]
pub struct Deployment {
    pub metadata: Metadata,
    pub spec: DeploymentSpec,
    pub status: DeploymentStatus,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentList {
    pub items: Vec<Deployment>,
}

// Services
fn tcp_str() -> String {
    "TCP".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct ServicePort {
    pub name: Option<String>,
    #[serde(rename = "nodePort")] pub node_port: Option<u32>,
    pub port: u32,
    #[serde(default = "tcp_str")] pub protocol: String,
    #[serde(rename = "targetPort")] pub target_pod: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceSpec {
    #[serde(rename = "clusterIP")] pub cluster_ip: Option<String>,
    #[serde(rename = "externalIPs")] pub external_ips: Option<Vec<String>>,
    pub ports: Option<Vec<ServicePort>>,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub metadata: Metadata,
    pub spec: ServiceSpec,
    pub status: Value,
}

#[derive(Debug, Deserialize)]
pub struct ServiceList {
    pub items: Vec<Service>,
}

// Namespaces
#[derive(Debug, Deserialize)]
pub struct NamespaceStatus {
    pub phase: String,
}

#[derive(Debug, Deserialize)]
pub struct Namespace {
    pub metadata: Metadata,
    pub status: NamespaceStatus,
}

#[derive(Debug, Deserialize)]
pub struct NamespaceList {
    pub items: Vec<Namespace>,
}

// ReplicaSets
#[derive(Debug, Deserialize)]
pub struct ReplicaSetList {
    pub items: Vec<Value>,
}

// ConfigMaps
#[derive(Debug, Deserialize)]
pub struct ConfigMapList {
    pub items: Vec<Value>,
}

// Secrets
#[derive(Debug, Deserialize)]
pub struct SecretList {
    pub items: Vec<Value>,
}

// Kubernetes authentication data

// Auth is either a token, a username/password, or a cert and key
pub enum KlusterAuth {
    Token(String),
    UserPass(String, String),
    CertKey(Vec<Certificate>, PrivateKey),
    AuthProvider(AuthProvider),
}

impl KlusterAuth {
    pub fn with_token(token: &str) -> KlusterAuth {
        KlusterAuth::Token(token.to_owned())
    }

    pub fn with_userpass(user: &str, pass: &str) -> KlusterAuth {
        KlusterAuth::UserPass(user.to_owned(), pass.to_owned())
    }

    pub fn with_cert_and_key(cert: Certificate, private_key: PrivateKey) -> KlusterAuth {
        KlusterAuth::CertKey(vec![cert], private_key)
    }

    pub fn with_auth_provider(auth_provider: AuthProvider) -> KlusterAuth {
        KlusterAuth::AuthProvider(auth_provider)
    }
}

pub struct Kluster {
    pub name: String,
    endpoint: Url,
    auth: KlusterAuth,
    client: Client,
    connector: ClickSslConnector<TlsClient>,
}

// NoCertificateVerification struct/impl taken from the rustls example code
struct NoCertificateVerification {}
impl rustls::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: &str,
    ) -> Result<(), rustls::TLSError> {
        Ok(())
    }
}

impl Kluster {
    fn make_tlsclient(cert_opt: &Option<String>, auth: &KlusterAuth, insecure: bool) -> TlsClient {
        let mut tlsclient = TlsClient::new();
        if let Some(cfg) = Arc::get_mut(&mut tlsclient.cfg) {
            if let &Some(ref cert_data) = cert_opt {
                // add the cert to the root store
                let mut br = BufReader::new(cert_data.as_bytes());
                match cfg.root_store.add_pem_file(&mut br) {
                    Ok(added) => {
                        if added.1 > 0 {
                            println!(
                                "[WARNING] Couldn't add your server cert, connection will probably \
                                 fail"
                            );
                        }
                    }
                    Err(e) => println!(
                        "[WARNING] Coudln't add your server cert, connection will probably \
                         fail. Error was: {:?}",
                        e
                    ),
                }
            }

            if let &KlusterAuth::CertKey(ref cert, ref key) = auth {
                cfg.set_single_client_cert(cert.clone(), key.clone());
            }

            if insecure {
                cfg.dangerous()
                    .set_certificate_verifier(Box::new(NoCertificateVerification {}));
            }
        } else {
            println!(
                "[WARNING] Failed to configure tlsclient, connection will probably fail.  \
                 Please restart click"
            );
        }
        tlsclient
    }

    fn get_host_ip(endpoint: &mut Url) -> (Option<String>, Option<String>) {
        let mut dns_host: Option<String> = None;
        let mut ip: Option<String> = None;
        if let Some(host) = endpoint.host_str() {
            if let Ok(addr) = IpAddr::from_str(host) {
                dns_host = ::certs::try_ip_to_name(&addr, endpoint.port().unwrap_or(443));
                ip = Some(host.to_owned());
            }
        };
        if let (Some(ref host), Some(ref _ip_addr)) = (dns_host.as_ref(), ip.as_ref()) {
            // The cert has a matching IP and a host name, use that
            endpoint.set_host(Some(host.as_str())).unwrap();
        }
        (dns_host, ip)
    }

    // We map ip addresses to a name in the certificate if needed, to keep hyper happy.  see
    // comments on try_ip_to_name and in connector.rs.
    fn make_connector(
        tlsclient: TlsClient,
        dns_host: Option<String>,
        ip: Option<String>,
    ) -> ClickSslConnector<TlsClient> {
        if let (Some(host), Some(ip_addr)) = (dns_host, ip) {
            ClickSslConnector::new(tlsclient, Some((host, ip_addr)))
        } else {
            ClickSslConnector::new(tlsclient, None)
        }
    }

    fn add_auth_header<'a>(&self, req: RequestBuilder<'a>) -> RequestBuilder<'a> {
        match self.auth {
            KlusterAuth::Token(ref token) => req.header(Authorization(Bearer {
                token: token.clone(),
            })),
            KlusterAuth::AuthProvider(ref auth_provider) => {
                let token = auth_provider.ensure_token();
                req.header(Authorization(Bearer { token: token }))
            }
            KlusterAuth::UserPass(ref user, ref pass) => req.header(Authorization(Basic {
                username: user.clone(),
                password: Some(pass.clone()),
            })),
            KlusterAuth::CertKey(..) => req,
        }
    }

    pub fn new(
        name: &str,
        cert_opt: Option<String>,
        server: &str,
        auth: KlusterAuth,
        insecure: bool,
    ) -> Result<Kluster, KubeError> {
        let tlsclient = Kluster::make_tlsclient(&cert_opt, &auth, insecure);
        let tlsclient2 = Kluster::make_tlsclient(&cert_opt, &auth, insecure);
        let mut endpoint = try!(Url::parse(server));
        let (dns_host, ip) = Kluster::get_host_ip(&mut endpoint);
        let mut client = Client::with_connector(Kluster::make_connector(
            tlsclient,
            dns_host.clone(),
            ip.clone(),
        ));
        client.set_read_timeout(Some(Duration::new(20, 0)));
        client.set_write_timeout(Some(Duration::new(20, 0)));
        Ok(Kluster {
            name: name.to_owned(),
            endpoint: endpoint,
            auth: auth,
            client: client,
            connector: Kluster::make_connector(tlsclient2, dns_host, ip),
        })
    }

    fn send_req(&self, path: &str) -> Result<Response, KubeError> {
        let url = try!(self.endpoint.join(path));
        let req = self.client.get(url);
        let req = self.add_auth_header(req);
        req.send().map_err(|he| KubeError::from(he))
    }

    fn check_resp(&self, resp: Response) -> Result<Response, KubeError> {
        if resp.status == StatusCode::Ok {
            Ok(resp)
        } else if resp.status == StatusCode::Unauthorized {
            Err(KubeError::Kube(KubeErrNo::Unauthorized))
        } else {
            // try and read an error message out
            let val: Value = try!(serde_json::from_reader(resp));
            match ::values::val_str_opt("/message", &val) {
                Some(msg) => Err(KubeError::KubeServerError(msg)),
                None => Err(KubeError::Kube(KubeErrNo::Unknown)),
            }
        }
    }

    /// Get a resource and deserialize it as a T
    pub fn get<T>(&self, path: &str) -> Result<T, KubeError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let resp = try!(self.send_req(path));
        let resp = try!(self.check_resp(resp));
        serde_json::from_reader(resp).map_err(|sje| KubeError::from(sje))
    }

    /// Get a Response.  Response implements Read, so this allows for a streaming read (for things
    /// like printing logs)
    pub fn get_read(&self, path: &str, timeout: Option<Duration>) -> Result<Response, KubeError> {
        if timeout.is_some() {
            let url = try!(self.endpoint.join(path));
            let mut req = try!(Request::with_connector(Method::Get, url, &self.connector,));
            {
                // scope for mutable borrow of req
                let headers = req.headers_mut();
                // we should clean this up to use add_auth_header
                match self.auth {
                    KlusterAuth::Token(ref token) => {
                        headers.set(Authorization(Bearer {
                            token: token.clone(),
                        }));
                    }
                    KlusterAuth::AuthProvider(ref auth_provider) => {
                        let token = auth_provider.ensure_token();
                        headers.set(Authorization(Bearer {
                            token: token.clone(),
                        }));
                    }
                    KlusterAuth::UserPass(ref user, ref pass) => {
                        headers.set(Authorization(Basic {
                            username: user.clone(),
                            password: Some(pass.clone()),
                        }));
                    }
                    KlusterAuth::CertKey(..) => {}
                }
            }
            try!(req.set_read_timeout(timeout));
            let next = try!(req.start());
            let resp = try!(next.send().map_err(|he| KubeError::from(he)));
            self.check_resp(resp)
        } else {
            let resp = try!(self.send_req(path));
            self.check_resp(resp)
        }
    }

    /// Get a serde_json::Value
    pub fn get_value(&self, path: &str) -> Result<Value, KubeError> {
        let resp = try!(self.send_req(path));
        let resp = try!(self.check_resp(resp));
        serde_json::from_reader(resp).map_err(|sje| KubeError::from(sje))
    }

    /// Issue an HTTP DELETE request to the specified path
    pub fn delete(&self, path: &str, body: Option<String>) -> Result<Response, KubeError> {
        let url = try!(self.endpoint.join(path));
        let req = self.client.delete(url);
        let req = match body {
            Some(ref b) => {
                let hyper_body = Body::BufBody(b.as_bytes(), b.len());
                req.body(hyper_body)
            }
            None => req,
        };
        let req = self.add_auth_header(req);
        req.send().map_err(|he| KubeError::from(he))
    }

    /// Get all namespaces in this cluster
    pub fn namespaces_for_context(&self) -> Result<Vec<String>, KubeError> {
        let mut vec = Vec::new();
        let res = try!(self.get::<NamespaceList>("/api/v1/namespaces"));
        for ns in res.items.iter() {
            vec.push(ns.metadata.name.clone());
        }
        Ok(vec)
    }
}
