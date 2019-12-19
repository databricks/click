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

//!  Utility functions for the Describe command, used to output
//!  information for supported kubernetes object types

use values::{val_str, val_str_opt, val_u64};

use ansi_term::Colour;
use chrono::DateTime;
use chrono::offset::Local;
use chrono::offset::Utc;
use serde_json::Value;

use std::borrow::Cow;
use std::fmt::Write;
use std::str::{self, FromStr};

pub enum DescItem<'a> {
    ValStr {
        path: &'a str,
        default: &'a str,
    },
    KeyValStr {
        parent: &'a str,
        secret_vals: bool,
    },
    MetadataValStr {
        path: &'a str,
        default: &'a str,
    },
    ObjectCreated,
    CustomFunc {
        path: Option<&'a str>,
        func: &'a (dyn Fn(&Value) -> Cow<str>),
        default: &'a str,
    },
    StaticStr(Cow<'a, str>),
}

/// get key/vals out of a value
/// If secret_vals is true, the actual vals are hidden and we show only the size of the value
fn keyval_str<'a>(v: &'a Value, parent: &str, secret_vals: bool) -> Cow<'a, str> {
    let mut outstr = String::new();
    match v.pointer(parent) {
        Some(p) => {
            if let Some(keyvals) = p.as_object() {
                let mut first = true;
                for key in keyvals.keys() {
                    if !first {
                        outstr.push('\n');
                        if !secret_vals {
                            outstr.push('\t');
                        }
                    }
                    first = false;
                    outstr.push('\t');
                    outstr.push_str(key);

                    let is_service_token = if secret_vals && key == "token" {
                        let typ = v.pointer("/type").and_then(|t| t.as_str()).unwrap_or("");
                        typ == "kubernetes.io/service-account-token"
                    } else {
                        false
                    };

                    if is_service_token {
                        outstr.push_str(":\t");
                        match ::base64::decode(keyvals.get(key).unwrap().as_str().unwrap()) {
                            Ok(dec) => outstr
                                .push_str(str::from_utf8(&dec[..]).unwrap_or("Invalid utf-8 data")),
                            Err(_) => outstr.push_str("Could not decode secret"),
                        }
                    } else if secret_vals {
                        outstr.push_str(":\t");
                        match ::base64::decode(keyvals.get(key).unwrap().as_str().unwrap()) {
                            Ok(dec) => outstr.push_str(format!("{} bytes", dec.len()).as_str()),
                            Err(_) => outstr.push_str("Could not decode secret"),
                        }
                    } else {
                        outstr.push('=');
                        outstr.push_str(keyvals.get(key).unwrap().as_str().unwrap());
                    }
                }
            }
        }
        None => {
            outstr.push_str("\t<none>");
        }
    }
    outstr.into()
}

/// Generic describe function
/// TODO: Document
pub fn describe_object<'a, I>(v: &Value, fields: I) -> String
where
    I: Iterator<Item = (&'a str, DescItem<'a>)>,
{
    let mut res = String::new();
    let metadata = v.get("metadata").unwrap();
    for (title, item) in fields {
        let val = match item {
            DescItem::ValStr {
                ref path,
                ref default,
            } => val_str(path, v, default),
            DescItem::KeyValStr {
                ref parent,
                secret_vals,
            } => keyval_str(v, parent, secret_vals),
            DescItem::MetadataValStr {
                ref path,
                ref default,
            } => val_str(path, metadata, default),
            DescItem::ObjectCreated => {
                let created: DateTime<Utc> = DateTime::from_str(&val_str(
                    "/creationTimestamp",
                    metadata,
                    "<No CreationTime>",
                )).unwrap();
                format!("{} ({})", created, created.with_timezone(&Local)).into()
            }
            DescItem::CustomFunc {
                ref path,
                ref func,
                default,
            } => {
                let value = match path {
                    &Some(p) => v.pointer(p),
                    &None => Some(v),
                };
                match value {
                    Some(v) => func(v),
                    None => default.into(),
                }
            }
            DescItem::StaticStr(s) => s,
        };
        write!(&mut res, "{}{}\n", title, val).unwrap();
    }
    res
}

/// Utility function for describe to print out value
pub fn describe_format_pod(v: Value) -> String {
    let fields = vec![
        (
            "Name:\t\t",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Namespace:\t",
            DescItem::MetadataValStr {
                path: "/namespace",
                default: "<No Name>",
            },
        ),
        (
            "Node:\t\t",
            DescItem::ValStr {
                path: "/spec/nodeName",
                default: "<No NodeName>",
            },
        ),
        (
            "IP:\t\t",
            DescItem::ValStr {
                path: "/status/podIP",
                default: "<No PodIP>",
            },
        ),
        ("Created at:\t", DescItem::ObjectCreated),
        (
            "Status:\t\t",
            DescItem::CustomFunc {
                path: None,
                func: &pod_phase,
                default: "<No Phase>",
            },
        ),
        (
            "Labels:\t",
            DescItem::KeyValStr {
                parent: "/metadata/labels",
                secret_vals: false,
            },
        ),
        (
            "Annotations:",
            DescItem::KeyValStr {
                parent: "/metadata/annotations",
                secret_vals: false,
            },
        ),
        (
            "Volumes:\n",
            DescItem::CustomFunc {
                path: Some("/spec/volumes"),
                func: &get_volume_str,
                default: "<No Volumes>",
            },
        ),
    ];
    describe_object(&v, fields.into_iter())
}

/// Get volume info out of volume array
fn get_volume_str<'a>(v: &'a Value) -> Cow<'a, str> {
    let mut buf = String::new();
    if let Some(vol_arry) = v.as_array() {
        for vol in vol_arry.iter() {
            buf.push_str(format!("  Name: {}\n", val_str("/name", vol, "<No Name>")).as_str());
            if vol.get("emptyDir").is_some() {
                buf.push_str(
                    "    Type:\tEmptyDir (a temporary directory that shares a pod's lifetime)\n",
                )
            }
            if let Some(conf_map) = vol.get("configMap") {
                buf.push_str("    Type:\tConfigMap (a volume populated by a ConfigMap)\n");
                buf.push_str(
                    format!("    Name:\t{}\n", val_str("/name", conf_map, "<No Name>")).as_str(),
                );
            }
            if let Some(secret) = vol.get("secret") {
                buf.push_str("    Type:\tSecret (a volume populated by a Secret)\n");
                buf.push_str(
                    format!(
                        "    SecretName:\t{}\n",
                        val_str("/secretName", secret, "<No SecretName>")
                    ).as_str(),
                );
            }
            if let Some(aws) = vol.get("awsElasticBlockStore") {
                buf.push_str(
                    "    Type:\tAWS Block Store (An AWS Disk resource exposed to the pod)\n",
                );
                buf.push_str(
                    format!(
                        "    VolumeId:\t{}\n",
                        val_str("/volumeID", aws, "<No VolumeID>")
                    ).as_str(),
                );
                buf.push_str(
                    format!("    FSType:\t{}\n", val_str("/fsType", aws, "<No FsType>")).as_str(),
                );
                let mut pnum = 0;
                if let Some(part) = aws.get("partition") {
                    if let Some(p) = part.as_u64() {
                        pnum = p;
                    }
                }
                buf.push_str(format!("    Partition#:\t{}\n", pnum).as_str());
                if let Some(read_only) = aws.get("readOnly") {
                    if read_only.as_bool().unwrap() {
                        buf.push_str("    Read-Only:\tTrue\n");
                    } else {
                        buf.push_str("    Read-Only:\tFalse\n");
                    }
                } else {
                    buf.push_str("    Read-Only:\tFalse\n");
                }
            }
        }
    }
    buf.into()
}

fn pod_phase<'a>(v: &Value) -> Cow<str> {
    let phase_str = val_str("/status/phase", v, "<No Phase>");
    let colour = match &*phase_str {
        "Pending" | "Unknown" => Colour::Yellow,
        "Running" | "Succeeded" => Colour::Green,
        "Failed" => Colour::Red,
        _ => Colour::Yellow,
    };
    colour.paint(phase_str).to_string().into()
}

/// Utility function for describe to print out value
pub fn describe_format_node(v: Value) -> String {
    let fields = vec![
        (
            "Name:\t\t",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Labels:\t",
            DescItem::KeyValStr {
                parent: "/metadata/labels",
                secret_vals: false,
            },
        ),
        (
            "Annotations:",
            DescItem::KeyValStr {
                parent: "/metadata/annotations",
                secret_vals: false,
            },
        ),
        ("Created at:\t", DescItem::ObjectCreated),
        (
            "Provider Id:\t",
            DescItem::ValStr {
                path: "/spec/providerID",
                default: "<No Provider Id>",
            },
        ),
        (
            "External URL:\t",
            DescItem::CustomFunc {
                path: None,
                func: &node_access_url,
                default: "N/A>",
            },
        ),
        (
            "\nSystem Info:",
            DescItem::KeyValStr {
                parent: "/status/nodeInfo",
                secret_vals: false,
            },
        ),
    ];
    describe_object(&v, fields.into_iter())
}

fn node_access_url<'a>(v: &'a Value) -> Cow<'a, str> {
    match val_str_opt("/spec/providerID", v) {
        Some(provider) => {
            if provider.starts_with("aws://") {
                let ip_opt = v.pointer("/status/addresses").and_then(|addr| {
                    addr.as_array().and_then(|addr_vec| {
                        addr_vec
                            .into_iter()
                            .find(|&aval| {
                                aval.as_object().map_or(false, |addr| {
                                    addr["type"].as_str().map_or(false, |t| t == "ExternalIP")
                                })
                            })
                            .and_then(|v| v.pointer("/address").and_then(|a| a.as_str()))
                    })
                });
                ip_opt.map_or("Not Found".into(), |ip| {
                    let octs: Vec<&str> = ip.split(".").collect();
                    if octs.len() < 4 {
                        format!("Unexpected ip format: {}", ip).into()
                    } else {
                        format!(
                            "ec2-{}-{}-{}-{}.us-west-2.compute.amazonaws.com ({})",
                            octs[0], octs[1], octs[2], octs[3], ip
                        ).into()
                    }
                })
            } else {
                "N/A".into()
            }
        }
        None => "N/A".into(),
    }
}

/// Utility function for describe to print service info
pub fn describe_format_service(v: Value, endpoint_val: Option<Value>) -> String {
    let port_str = get_ports_str(v.pointer("/spec/ports"), endpoint_val);
    let fields = vec![
        (
            "Name:\t\t",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Labels:\t",
            DescItem::KeyValStr {
                parent: "/metadata/labels",
                secret_vals: false,
            },
        ),
        (
            "Annotations:",
            DescItem::KeyValStr {
                parent: "/metadata/annotations",
                secret_vals: false,
            },
        ),
        ("Created at:\t", DescItem::ObjectCreated),
        (
            "Selector:",
            DescItem::KeyValStr {
                parent: "/spec/selector",
                secret_vals: false,
            },
        ),
        (
            "Type:\t\t",
            DescItem::ValStr {
                path: "/spec/type",
                default: "<No Type>",
            },
        ),
        (
            "IP:\t\t",
            DescItem::ValStr {
                path: "/spec/clusterIP",
                default: "<No Type>",
            },
        ),
        (
            "LoadBalIngress:\t",
            DescItem::ValStr {
                path: "/status/loadBalancer/ingress/0/hostname",
                default: "<No Ingress>",
            },
        ),
        ("Ports:\n", DescItem::StaticStr(port_str)),
        (
            "SessionAffnity:\t",
            DescItem::ValStr {
                path: "/spec/sessionAffnity",
                default: "<none>",
            },
        ),
    ];
    describe_object(&v, fields.into_iter())
}

/// Get ports info out of ports array
fn get_ports_str<'a>(v: Option<&'a Value>, endpoint_val: Option<Value>) -> Cow<'a, str> {
    if v.is_none() {
        return "<none>".into();
    }
    let mut buf = String::new();
    match v.unwrap().as_array() {
        // safe unwrap, checked above
        Some(port_array) => {
            for port in port_array.iter() {
                let proto = val_str("/protocol", port, "<Unknown>");
                let name = val_str("/name", port, "<No Name>");
                let port_num = val_u64("/port", port, 0);
                let endpoints = match endpoint_val {
                    Some(ref ep) => {
                        // to get all the endpoints, we need to check all subsets this port is in
                        // TODO: This is complex, simplify and/or abstract
                        let mut epbuf = String::from_str("  Endpoints:\t").unwrap();
                        let mut found_one = false;
                        ep.pointer("/subsets").map(|s| {
                            s.as_array().map(|subsets| {
                                for subset in subsets.iter() {
                                    // see if this subset has this port by checking if any port in
                                    // the ports array has the same port number
                                    let contains = subset
                                        .pointer("/ports")
                                        .map(|p| {
                                            p.as_array()
                                                .map(|ports_array| {
                                                    let mut c = false;
                                                    for port in ports_array.iter() {
                                                        if port_num == val_u64("/port", port, 0) {
                                                            c = true;
                                                        }
                                                    }
                                                    c
                                                })
                                                .unwrap_or(false)
                                        })
                                        .unwrap_or(false);
                                    if contains {
                                        // we do have this port, need to add all addresses as
                                        // endpoints
                                        found_one = true;
                                        let port_num = val_u64("/targetPort", port, 0);
                                        subset.pointer("/addresses").map(|a| {
                                            a.as_array().map(|addr_array| {
                                                let mut first = true;
                                                for addr in addr_array.iter() {
                                                    if first {
                                                        first = false;
                                                    } else {
                                                        epbuf.push_str(", ");
                                                    }
                                                    epbuf.push_str(
                                                        format!("{}:{}",
                                                                val_str("/ip", addr, "<No IP>"),
                                                                port_num).as_str());
                                                }
                                            })
                                        });
                                    }
                                }
                            })
                        });
                        if !found_one {
                            epbuf.push_str("<none>");
                        }
                        epbuf
                    }
                    None => "<No Endpoints>".to_owned(),
                };
                buf.push_str(format!("  Port:\t\t{} {}/{}\n", name, port_num, proto).as_str());
                buf.push_str(
                    format!(
                        "  NodePort:\t{} {}/{}\n",
                        val_str("/name", port, "<No Name>"),
                        val_u64("/nodePort", port, 0),
                        proto
                    ).as_str(),
                );
                buf.push_str(endpoints.as_str());
                buf.push('\n');
                buf.push('\n');
            }
        }
        None => buf.push_str("<none>"),
    }
    buf.into()
}

/// Utility function to describe a secret
pub fn describe_format_secret(v: Value) -> String {
    let fields = vec![
        (
            "Name:\t\t",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Namespace:\t",
            DescItem::MetadataValStr {
                path: "/namespace",
                default: "<No Name>",
            },
        ),
        (
            "Labels:\t",
            DescItem::KeyValStr {
                parent: "/metadata/labels",
                secret_vals: false,
            },
        ),
        (
            "Annotations:",
            DescItem::KeyValStr {
                parent: "/metadata/annotations",
                secret_vals: false,
            },
        ),
        (
            "\nType:\t\t",
            DescItem::ValStr {
                path: "/type",
                default: "<No Type>",
            },
        ),
        (
            "\nData:\n",
            DescItem::KeyValStr {
                parent: "/data",
                secret_vals: true,
            },
        ),
    ];
    describe_object(&v, fields.into_iter())
}
