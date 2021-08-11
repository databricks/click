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
use chrono::offset::Utc;
use chrono::DateTime;
use hyper::client::request::Request;
use hyper::client::response::Response;
use hyper::client::{Body, RequestBuilder};
use hyper::error::Error as HyperError;
use hyper::header::{Authorization, Basic, Bearer};
use hyper::method::Method;
use hyper::status::StatusCode;
use hyper::{Client, Url};
use hyper_sync_rustls::TlsClient;
use rustls::{self, Certificate, PrivateKey};
use serde::Deserialize;
use serde_json;
use serde_json::{Map, Value};

use std::cell::RefCell;
use std::fmt;
use std::io::BufReader;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use config::{AuthProvider, ExecAuth, ExecProvider};
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
    #[serde(rename = "creationTimestamp")]
    pub creation_timestamp: Option<DateTime<Utc>>,
    #[serde(rename = "deletionTimestamp")]
    pub deletion_timestamp: Option<DateTime<Utc>>,
    pub labels: Option<Map<String, Value>>,
    pub annotations: Option<Map<String, Value>>,
    #[serde(rename = "ownerReferences")]
    pub owner_refs: Option<Vec<OwnerReference>>,
}

// Code to easily create a namespace in a test
impl Metadata {
    #[cfg(test)]
    pub fn with_name(name: &str) -> Metadata {
        Metadata {
            name: name.to_string(),
            namespace: None,
            creation_timestamp: None,
            deletion_timestamp: None,
            labels: None,
            annotations: None,
            owner_refs: None,
        }
    }
}

// pods

#[derive(Debug, Deserialize)]
pub enum ContainerState {
    #[serde(rename = "running")]
    Running {
        #[serde(rename = "startedAt")]
        started_at: Option<DateTime<Utc>>,
    },
    #[serde(rename = "terminated")]
    Terminated {
        #[serde(rename = "containerId")]
        container_id: Option<String>,
        #[serde(rename = "exitCode")]
        exit_code: u32,
        #[serde(rename = "finishedAt")]
        finished_at: Option<DateTime<Utc>>,
        message: Option<String>,
        reason: Option<String>,
        signal: Option<u32>,
        #[serde(rename = "startedAt")]
        started_at: Option<DateTime<Utc>>,
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
            ContainerState::Running { started_at } => match started_at {
                Some(sa) => write!(f, "{} (started: {})", Green.paint("running"), sa),
                None => write!(f, "{} (unknown start time)", Green.paint("running")),
            },
            ContainerState::Terminated {
                ref exit_code,
                ref finished_at,
                ..
            } => match finished_at {
                Some(fa) => write!(
                    f,
                    "{} at {} (exit code: {})",
                    Red.paint("terminated"),
                    fa,
                    exit_code
                ),
                None => write!(
                    f,
                    "{} (time unknown) (exit code: {})",
                    Red.paint("terminated"),
                    exit_code
                ),
            },
            ContainerState::Waiting { ref reason, .. } => write!(
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
    #[serde(rename = "containerID")]
    pub id: Option<String>,
    pub name: String,
    pub image: String,
    #[serde(rename = "restartCount")]
    pub restart_count: u32,
    pub ready: bool,
    pub state: ContainerState,
}

#[derive(Debug, Deserialize)]
pub struct PodStatus {
    pub phase: String,
    #[serde(rename = "containerStatuses")]
    pub container_statuses: Option<Vec<ContainerStatus>>,
}

#[derive(Debug, Deserialize)]
pub struct VolumeMount {
    #[serde(rename = "mountPath")]
    pub mount_path: String,
    pub name: String,
    #[serde(rename = "readOnly")]
    pub read_only: Option<bool>,
    #[serde(rename = "subPath")]
    pub sub_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub args: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    #[serde(rename = "volumeMounts")]
    pub volume_mounts: Option<Vec<VolumeMount>>,
}

#[derive(Debug, Deserialize)]
pub struct PodSpec {
    pub hostname: Option<String>,
    #[serde(rename = "nodeName")]
    pub node_name: Option<String>,
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
    pub count: Option<u32>,
    pub message: String,
    pub reason: String,
    #[serde(rename = "lastTimestamp")]
    pub last_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct EventList {
    pub items: Vec<Event>,
}

// Nodes
#[derive(Debug, Deserialize)]
pub struct NodeCondition {
    #[serde(rename = "type")]
    pub typ: String,
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
    #[serde(default = "replicas_one")]
    pub replicas: u32,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentStatus {
    #[serde(default = "replicas_none")]
    pub replicas: u32,
    #[serde(default = "replicas_none", rename = "availableReplicas")]
    pub available: u32,
    #[serde(default = "replicas_none", rename = "updatedReplicas")]
    pub updated: u32,
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
    #[serde(rename = "nodePort")]
    pub node_port: Option<u32>,
    pub port: u32,
    #[serde(default = "tcp_str")]
    pub protocol: String,
    #[serde(rename = "targetPort")]
    pub target_pod: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceSpec {
    #[serde(rename = "clusterIP")]
    pub cluster_ip: Option<String>,
    #[serde(rename = "externalIPs")]
    pub external_ips: Option<Vec<String>>,
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

// StatefulSets
#[derive(Debug, Deserialize)]
pub struct StatefulSetList {
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

// Jobs
#[derive(Debug, Deserialize)]
pub struct JobList {
    pub items: Vec<Value>,
}

// Kubernetes authentication data

// Auth is either a token, a username/password, or an auth provider
pub enum KlusterAuth {
    Token(String),
    UserPass(String, String),
    AuthProvider(Box<AuthProvider>),
    ExecProvider(ExecProvider),
}

impl KlusterAuth {
    pub fn with_token(token: &str) -> KlusterAuth {
        KlusterAuth::Token(token.to_owned())
    }

    pub fn with_userpass(user: &str, pass: &str) -> KlusterAuth {
        KlusterAuth::UserPass(user.to_owned(), pass.to_owned())
    }

    pub fn with_auth_provider(auth_provider: AuthProvider) -> KlusterAuth {
        KlusterAuth::AuthProvider(Box::new(auth_provider))
    }

    pub fn with_exec_provider(exec_provider: ExecProvider) -> KlusterAuth {
        KlusterAuth::ExecProvider(exec_provider)
    }
}

// Hold the client cert and key for talking to the cluster
pub struct ClientCertKey {
    certs: Vec<Certificate>,
    key: PrivateKey,
}

impl ClientCertKey {
    pub fn with_cert_and_key(cert: Certificate, private_key: PrivateKey) -> ClientCertKey {
        ClientCertKey {
            certs: vec![cert],
            key: private_key,
        }
    }
}

// Hold either a Bearer or Basic auth header
enum AuthHeader {
    Basic(Basic),
    Bearer(Bearer),
}

pub struct Kluster {
    pub name: String,
    endpoint: Url,
    auth: Option<KlusterAuth>,
    root_cert: Option<String>,
    client_cert_key: Option<ClientCertKey>,
    insecure: bool,
    client: RefCell<Client>,
    connector: RefCell<ClickSslConnector<TlsClient>>,
}

// NoCertificateVerification struct/impl taken from the rustls example code
pub struct NoCertificateVerification {}
impl rustls::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

impl Kluster {
    fn make_tlsclient(
        cert_opt: &Option<String>,
        client_cert_key: &Option<ClientCertKey>,
        insecure: bool,
    ) -> TlsClient {
        let mut tlsclient = TlsClient::new();
        if let Some(cfg) = Arc::get_mut(&mut tlsclient.cfg) {
            if let Some(ref cert_data) = *cert_opt {
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

            if let Some(client_cert_key) = client_cert_key {
                cfg.set_single_client_cert(
                    client_cert_key.certs.clone(),
                    client_cert_key.key.clone(),
                );
            }

            if insecure {
                cfg.dangerous()
                    .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
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
        if let (Some(host), Some(_ip_addr)) = (dns_host.as_ref(), ip.as_ref()) {
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
        connect_timeout: Duration,
    ) -> ClickSslConnector<TlsClient> {
        if let (Some(host), Some(ip_addr)) = (dns_host, ip) {
            ClickSslConnector::new(tlsclient, Some((host, ip_addr)), connect_timeout)
        } else {
            ClickSslConnector::new(tlsclient, None, connect_timeout)
        }
    }

    fn create_new_client(&self, client_cert_key: &Option<ClientCertKey>) {
        // need a new cert/key, so make a new client
        let tlsclient = Kluster::make_tlsclient(&self.root_cert, client_cert_key, self.insecure);
        let mut new_client =
            Client::with_connector(self.connector.borrow().copy(tlsclient.clone()));
        let new_connector = self.connector.borrow().copy(tlsclient);
        new_client.set_read_timeout(Some(Duration::new(20, 0)));
        new_client.set_write_timeout(Some(Duration::new(20, 0)));
        *self.client.borrow_mut() = new_client;
        *self.connector.borrow_mut() = new_connector;
    }

    fn handle_exec_provider(&self, exec_provider: &ExecProvider) {
        let (auth, was_expired) = exec_provider.get_auth();
        match auth {
            ExecAuth::Token(_) => {} // handled below
            ExecAuth::ClientCertKey { cert, key } => {
                if was_expired {
                    let client_cert_key = Some(ClientCertKey::with_cert_and_key(cert, key));
                    self.create_new_client(&client_cert_key);
                }
            }
        }
    }

    fn get_auth_header(&self) -> Option<AuthHeader> {
        match self.auth {
            Some(KlusterAuth::Token(ref token)) => Some(AuthHeader::Bearer(Bearer {
                token: token.clone(),
            })),
            Some(KlusterAuth::AuthProvider(ref auth_provider)) => {
                match auth_provider.ensure_token() {
                    Some(token) => Some(AuthHeader::Bearer(Bearer { token })),
                    None => {
                        print_token_err();
                        None
                    }
                }
            }
            Some(KlusterAuth::UserPass(ref user, ref pass)) => Some(AuthHeader::Basic(Basic {
                username: user.clone(),
                password: Some(pass.clone()),
            })),
            Some(KlusterAuth::ExecProvider(ref exec_provider)) => {
                let (auth, _) = exec_provider.get_auth();
                match auth {
                    ExecAuth::Token(token) => Some(AuthHeader::Bearer(Bearer { token })),
                    ExecAuth::ClientCertKey { .. } => None, // handled above
                }
            }
            None => None,
        }
    }

    fn add_auth_header<'a>(&self, req: RequestBuilder<'a>) -> RequestBuilder<'a> {
        match self.get_auth_header() {
            Some(AuthHeader::Basic(header)) => req.header(Authorization(header)),
            Some(AuthHeader::Bearer(header)) => req.header(Authorization(header)),
            None => req,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        cert_opt: Option<String>,
        server: &str,
        auth: Option<KlusterAuth>,
        client_cert_key: Option<ClientCertKey>,
        insecure: bool,
        connect_timeout_secs: u32,
        read_timeout_secs: u32,
    ) -> Result<Kluster, KubeError> {
        let tlsclient = Kluster::make_tlsclient(&cert_opt, &client_cert_key, insecure);
        let mut endpoint = Url::parse(server)?;
        let (dns_host, ip) = Kluster::get_host_ip(&mut endpoint);
        let mut client = Client::with_connector(Kluster::make_connector(
            tlsclient.clone(),
            dns_host.clone(),
            ip.clone(),
            Duration::new(connect_timeout_secs.into(), 0),
        ));
        client.set_read_timeout(Some(Duration::new(read_timeout_secs.into(), 0)));
        client.set_write_timeout(Some(Duration::new(read_timeout_secs.into(), 0)));
        Ok(Kluster {
            name: name.to_owned(),
            endpoint,
            auth,
            root_cert: cert_opt,
            client_cert_key,
            insecure,
            client: RefCell::new(client),
            connector: RefCell::new(Kluster::make_connector(
                tlsclient,
                dns_host,
                ip,
                Duration::new(connect_timeout_secs.into(), 0),
            )),
        })
    }

    fn send_req(&self, path: &str) -> Result<Response, HyperError> {
        let url = self.endpoint.join(path)?;
        if let Some(KlusterAuth::ExecProvider(ref exec_provider)) = self.auth {
            self.handle_exec_provider(exec_provider);
        }
        let client = self.client.borrow();
        let req = client.get(url);
        let req = self.add_auth_header(req);
        req.send()
    }

    fn send(&self, path: &str) -> Result<Response, KubeError> {
        match self.send_req(path) {
            Ok(resp) => Ok(resp),
            Err(e) => match &e {
                HyperError::Io(ref io_err) => {
                    if io_err.kind() == std::io::ErrorKind::ConnectionReset {
                        self.create_new_client(&self.client_cert_key);
                        self.send_req(path).map_err(KubeError::from)
                    } else {
                        Err(KubeError::from(e))
                    }
                }
                _ => Err(KubeError::from(e)),
            },
        }
    }

    fn check_resp(&self, resp: Response) -> Result<Response, KubeError> {
        if resp.status == StatusCode::Ok {
            Ok(resp)
        } else if resp.status == StatusCode::Unauthorized {
            Err(KubeError::Kube(KubeErrNo::Unauthorized))
        } else {
            // try and read an error message out
            let val: Value = serde_json::from_reader(resp)?;
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
        let resp = self.send(path)?;
        let resp = self.check_resp(resp)?;
        serde_json::from_reader(resp).map_err(KubeError::from)
    }

    /// Get a Response.  Response implements Read, so this allows for a streaming read (for things
    /// like printing logs)
    pub fn get_read(
        &self,
        path: &str,
        timeout: Option<Duration>,
        retry: bool,
    ) -> Result<Response, KubeError> {
        // this has to be implemented in this gross way since we can't set timeouts on invidual
        // requests on the client
        let url = self.endpoint.join(path)?;
        let mut req = Request::with_connector(Method::Get, url, &*self.connector.borrow())?;
        {
            // scope for mutable borrow of req
            let headers = req.headers_mut();
            match self.get_auth_header() {
                Some(AuthHeader::Basic(header)) => headers.set(Authorization(header)),
                Some(AuthHeader::Bearer(header)) => headers.set(Authorization(header)),
                None => {}
            };
        }
        // None here means don't timeout, which we set for logs follow
        req.set_read_timeout(timeout)?;
        match req.start()?.send() {
            Ok(resp) => self.check_resp(resp),
            Err(e) => match &e {
                HyperError::Io(ref io_err) => {
                    if retry && io_err.kind() == std::io::ErrorKind::ConnectionReset {
                        self.create_new_client(&self.client_cert_key);
                        self.get_read(path, timeout, false)
                    } else {
                        Err(KubeError::from(e))
                    }
                }
                _ => Err(KubeError::from(e)),
            },
        }
    }

    /// Get a serde_json::Value
    pub fn get_value(&self, path: &str) -> Result<Value, KubeError> {
        let resp = self.send(path)?;
        let resp = self.check_resp(resp)?;
        serde_json::from_reader(resp).map_err(KubeError::from)
    }

    /// Issue an HTTP DELETE request to the specified path
    pub fn delete(
        &self,
        path: &str,
        body: Option<&str>,
        retry: bool,
    ) -> Result<Response, KubeError> {
        match self.inner_delete(path, body) {
            Ok(resp) => Ok(resp),
            Err(e) => match &e {
                HyperError::Io(ref io_err) => {
                    if retry && io_err.kind() == std::io::ErrorKind::ConnectionReset {
                        self.create_new_client(&self.client_cert_key);
                        self.inner_delete(path, body).map_err(KubeError::from)
                    } else {
                        Err(KubeError::from(e))
                    }
                }
                _ => Err(KubeError::from(e)),
            },
        }
    }

    fn inner_delete(&self, path: &str, body: Option<&str>) -> Result<Response, HyperError> {
        let url = self.endpoint.join(path)?;
        if let Some(KlusterAuth::ExecProvider(ref exec_provider)) = self.auth {
            self.handle_exec_provider(exec_provider);
        }
        let client = self.client.borrow();
        let req = client.delete(url);
        let req = match body {
            Some(b) => {
                let hyper_body = Body::BufBody(b.as_bytes(), b.len());
                req.body(hyper_body)
            }
            None => req,
        };
        let req = self.add_auth_header(req);
        req.send()
    }

    /// Get all namespaces in this cluster
    pub fn namespaces_for_context(&self) -> Result<Vec<String>, KubeError> {
        let mut vec = Vec::new();
        let res = self.get::<NamespaceList>("/api/v1/namespaces")?;
        for ns in res.items.iter() {
            vec.push(ns.metadata.name.clone());
        }
        Ok(vec)
    }
}

fn print_token_err() {
    println!(
        "Couldn't get an authentication token. You can try exiting Click and \
         running a kubectl command against the cluster to refresh it. \
         Also please report this error on the Click github page."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_last_timestamp() {
        let event_list_json = r#"
{
  "kind": "EventList",
  "apiVersion": "v1",
  "metadata": {
    "selfLink": "/api/v1/namespaces/default/events",
    "resourceVersion": "123"
  },
  "items": [
    {
      "metadata": {
        "name": "test_pod.160c9d9f5b3dca2b",
        "namespace": "default",
        "selfLink": "/api/v1/namespaces/default/events/test_pod.160c9d9f5b3dca2b",
        "uid": "7b20eb20",
        "resourceVersion": "123",
        "creationTimestamp": "2020-05-07T02:21:16Z"
      },
      "involvedObject": {
        "kind": "Pod",
        "namespace": "default",
        "name": "test_pod",
        "uid": "951eab98",
        "apiVersion": "v1",
        "resourceVersion": "123"
      },
      "count": 3,
      "reason": "Scheduled",
      "message": "message about a pod",
      "source": {
        "component": "default-scheduler"
      },
      "firstTimestamp": null,
      "lastTimestamp": null,
      "type": "Normal",
      "eventTime": "2020-05-07T02:21:16.311067Z",
      "action": "Binding",
      "reportingInstance": "default-scheduler"
    }
  ]
}"#;
        let el: EventList = serde_json::from_str(event_list_json).unwrap();
        assert!(el.items.get(0).unwrap().last_timestamp.is_none());
    }
}
