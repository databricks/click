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

// This whole thing is a bit of a hack.  We want to be able to handle servers specified by IP, but
// webpki doesn't support validating IP address SANS.  So this class can be told to override a
// certain hostname->ip mapping.  In kube.rs we'll swap the IP for a valid hostname, and then here
// we'll turn it back into the right IP.  For servers not specified as IP addresses, this is just a
// passthrough.

use std::io;
use std::net::TcpStream;

use hyper::error::Result;
use hyper::net::{HttpStream, HttpsStream, NetworkConnector, SslClient};

pub struct ClickSslConnector<S: SslClient> {
    ssl: S,
    host_addr: Option<(String, String)>,
}

impl<S: SslClient> ClickSslConnector<S> {
    /// Create a new connector using the provided SSL implementation.  host_addr should be a tuple
    /// of (hostname,ip_address), and for that hostname we will short-circuit DNS and just map to
    /// the specified IP.
    pub fn new(s: S, host_addr: Option<(String, String)>) -> ClickSslConnector<S> {
        ClickSslConnector {
            ssl: s,
            host_addr: host_addr,
        }
    }

    fn click_connect(&self, host: &str, port: u16, scheme: &str) -> Result<HttpStream> {
        let addr = match self.host_addr {
            Some((ref target_host, ref ip)) => {
                if host == target_host {
                    (ip.as_str(), port)
                } else {
                    (host, port)
                }
            }
            None => (host, port),
        };
        Ok(match scheme {
            "http" => {
                let res = Ok(HttpStream(TcpStream::connect(&addr)?));
                res
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid scheme for Http",
            )),
        }?)
    }
}

impl<S: SslClient> NetworkConnector for ClickSslConnector<S> {
    type Stream = HttpsStream<S::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> Result<Self::Stream> {
        let stream = self.click_connect(host, port, "http")?;
        if scheme == "https" {
            self.ssl.wrap_client(stream, host).map(HttpsStream::Https)
        } else {
            Ok(HttpsStream::Http(stream))
        }
    }
}
