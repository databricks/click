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

use chrono::DateTime;
use chrono::offset::utc::UTC;
use serde::Deserialize;
use hyper::{Client,Url};
use hyper::client::response::Response;
use hyper::header::{Authorization, Bearer};
use hyper::net::HttpsConnector;

use serde_json;
use serde_json::Value;
use hyper_rustls;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;


use error::KubeError;

// Various things we can return

// pods
#[derive(Debug, Deserialize)]
pub struct PodMetadata {
    pub name: String,
    pub namespace: String
}

#[derive(Debug, Deserialize)]
pub struct PodStatus {
    pub phase: String,
}


#[derive(Debug, Deserialize)]
pub struct Pod {
    pub metadata: PodMetadata,
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
    #[serde(rename="lastTimestamp")]
    pub last_timestamp: DateTime<UTC>,
}

#[derive(Debug, Deserialize)]
pub struct EventList {
    pub items: Vec<Event>,
}

pub struct Kluster {
    pub name: String,
    endpoint: Url,
    token: String,
    client: Client,
}

impl Kluster {

    pub fn new(name: &str, cert_path: &str, server: &str, token: &str) -> Result<Kluster, KubeError> {
        let mut tlsclient = hyper_rustls::TlsClient::new();
        {
            // add the cert to the root store
            let mut cfg = Arc::get_mut(&mut tlsclient.cfg).unwrap();
            let f = File::open(cert_path).unwrap();
            let mut br = BufReader::new(f);
            let added = cfg.root_store.add_pem_file(&mut br).unwrap();
            if added.1 > 0 {
                println!("[WARNING] Couldn't add some certs from {}", cert_path);
            }
        }


        Ok(Kluster {
            name: name.to_owned(),
            endpoint: try!(Url::parse(server)),
            token: token.to_owned(),
            client: Client::with_connector(HttpsConnector::new(tlsclient)),
        })
    }

    fn send_req(&self, path: &str) -> Result<Response, KubeError> {
        let url = try!(self.endpoint.join(path));
        let req = self.client.get(url);
        let req = req.header(Authorization(
            Bearer {
                token: self.token.clone()
            }
        ));
        req.send().map_err(|he| KubeError::from(he))
    }

    pub fn get<T>(&self, path: &str) -> Result<T, KubeError>
        where T: Deserialize {

        let resp = try!(self.send_req(path));
        serde_json::from_reader(resp).map_err(|sje| KubeError::from(sje))
    }

    // pub fn get_text(&self, path: &str) -> Result<String, KubeError> {
    //     let mut resp = try!(self.send_req(path));
    //     let mut buf = String::new();
    //     resp.read_to_string(&mut buf).map(|_| buf).map_err(|ioe| KubeError::from(ioe))
    // }

    pub fn get_read(&self, path: &str) -> Result<Response, KubeError> {
        self.send_req(path)
    }

    pub fn get_value(&self, path: &str) -> Result<Value, KubeError> {
        let resp = try!(self.send_req(path));
        serde_json::from_reader(resp).map_err(|sje| KubeError::from(sje))
    }
}
