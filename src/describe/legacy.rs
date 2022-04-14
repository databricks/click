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

use crate::error::ClickError;
use crate::output::ClickWriter;
use crate::values::{val_str, val_str_opt, val_u64};

use ansi_term::Colour;
use chrono::offset::Local;
use chrono::offset::Utc;
use chrono::DateTime;
use k8s_openapi::api::core::v1 as api;
use serde_json::Value;

use std::borrow::Cow;
use std::io::Write;
use std::str::{self, FromStr};

pub enum DescItem<'a> {
    ValStr {
        path: &'a str,
        default: &'a str,
    },
    Valu64 {
        path: &'a str,
        default: u64,
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
            DescItem::ValStr { path, default } => val_str(path, v, default),
            DescItem::Valu64 { path, default } => val_u64(path, v, default).to_string().into(),
            DescItem::KeyValStr {
                parent,
                secret_vals,
            } => keyval_str(v, parent, secret_vals),
            DescItem::MetadataValStr { path, default } => val_str(path, metadata, default),
            DescItem::ObjectCreated => {
                let created: DateTime<Utc> = DateTime::from_str(&val_str(
                    "/creationTimestamp",
                    metadata,
                    "<No CreationTime>",
                ))
                .unwrap();
                format!("{} ({})", created, created.with_timezone(&Local)).into()
            }
            DescItem::CustomFunc {
                ref path,
                ref func,
                default,
            } => {
                let value = match path {
                    Some(p) => v.pointer(p),
                    None => Some(v),
                };
                match value {
                    Some(v) => func(v),
                    None => default.into(),
                }
            }
            DescItem::StaticStr(s) => s,
        };
        use std::fmt::Write;
        writeln!(&mut res, "{}{}", title, val).unwrap();
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
fn get_volume_str(v: &Value) -> Cow<str> {
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
                    )
                    .as_str(),
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
                    )
                    .as_str(),
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

fn pod_phase(v: &Value) -> Cow<str> {
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
pub fn describe_format_node(node: &api::Node, writer: &mut ClickWriter) -> Result<(), ClickError> {
    let v = serde_json::value::to_value(&node).unwrap();
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
                default: "<N/A>",
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
    let s = describe_object(&v, fields.into_iter());
    clickwriteln!(writer, "{}", s);
    Ok(())
}

fn node_access_url(v: &Value) -> Cow<str> {
    match val_str_opt("/spec/providerID", v) {
        Some(provider) => {
            if provider.starts_with("aws://") {
                let ip_opt = v.pointer("/status/addresses").and_then(|addr| {
                    addr.as_array().and_then(|addr_vec| {
                        addr_vec
                            .iter()
                            .find(|&aval| {
                                aval.as_object().map_or(false, |addr| {
                                    addr["type"].as_str().map_or(false, |t| t == "ExternalIP")
                                })
                            })
                            .and_then(|v| v.pointer("/address").and_then(|a| a.as_str()))
                    })
                });
                ip_opt.map_or("Not Found".into(), |ip| {
                    let octs: Vec<&str> = ip.split('.').collect();
                    if octs.len() < 4 {
                        format!("Unexpected ip format: {}", ip).into()
                    } else {
                        format!(
                            "ec2-{}-{}-{}-{}.us-west-2.compute.amazonaws.com ({})",
                            octs[0], octs[1], octs[2], octs[3], ip
                        )
                        .into()
                    }
                })
            } else {
                "N/A".into()
            }
        }
        None => "N/A".into(),
    }
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

/// Get container info out of container array
fn get_container_str(v: &Value) -> Cow<str> {
    let mut buf = String::new();
    if let Some(container_array) = v.as_array() {
        for container in container_array.iter() {
            buf.push_str(
                format!("  Name: {}\n", val_str("/name", container, "<No Name>")).as_str(),
            );
            buf.push_str(
                format!(
                    "    Image:\t{}\n",
                    val_str("/image", container, "<No Image>")
                )
                .as_str(),
            );
        }
    }
    buf.into()
}

/// Get status messages out of 'conditions' array
fn get_message_str(v: &Value) -> Cow<str> {
    let mut buf = String::new();
    if let Some(condition_array) = v.as_array() {
        for condition in condition_array.iter() {
            let msg = val_str("/message", condition, "<No Message>");
            let colour = match &*msg {
                "Deployment has minimum availability." => Colour::Green,
                _ => Colour::Yellow,
            };
            buf.push_str(format!("  Message: {}\n", colour.paint(msg)).as_str());
        }
    }
    buf.into()
}

/// Utility function to describe a deployment
pub fn describe_format_deployment(v: Value) -> String {
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
        ("Created at:\t", DescItem::ObjectCreated),
        (
            "Generation:\t",
            DescItem::Valu64 {
                path: "/metadata/generation",
                default: 0,
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
            "Desired Replicas:\t",
            DescItem::Valu64 {
                path: "/spec/replicas",
                default: 0,
            },
        ),
        (
            "Current Replicas:\t",
            DescItem::Valu64 {
                path: "/status/replicas",
                default: 0,
            },
        ),
        (
            "Up To Date Replicas:\t",
            DescItem::Valu64 {
                path: "/status/updatedReplicas",
                default: 0,
            },
        ),
        (
            "Available Replicas:\t",
            DescItem::Valu64 {
                path: "/status/availableReplicas",
                default: 0,
            },
        ),
        (
            "\nContainers:\n",
            DescItem::CustomFunc {
                path: Some("/spec/template/spec/containers"),
                func: &get_container_str,
                default: "<No Containers>",
            },
        ),
        (
            "Messages:\n",
            DescItem::CustomFunc {
                path: Some("/status/conditions"),
                func: &get_message_str,
                default: "<No Messages>",
            },
        ),
    ];
    describe_object(&v, fields.into_iter())
}

/// Utility function to describe a rollout
#[cfg(feature = "argorollouts")]
pub fn describe_format_rollout(v: Value) -> String {
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
        ("Created at:\t", DescItem::ObjectCreated),
        (
            "Generation:\t",
            DescItem::Valu64 {
                path: "/metadata/generation",
                default: 0,
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
            "Desired Replicas:\t",
            DescItem::Valu64 {
                path: "/spec/replicas",
                default: 0,
            },
        ),
        (
            "Current Replicas:\t",
            DescItem::Valu64 {
                path: "/status/replicas",
                default: 0,
            },
        ),
        (
            "Up To Date Replicas:\t",
            DescItem::Valu64 {
                path: "/status/updatedReplicas",
                default: 0,
            },
        ),
        (
            "Available Replicas:\t",
            DescItem::Valu64 {
                path: "/status/availableReplicas",
                default: 0,
            },
        ),
        (
            "\nContainers:\n",
            DescItem::CustomFunc {
                path: Some("/spec/template/spec/containers"),
                func: &get_container_str,
                default: "<No Containers>",
            },
        ),
        (
            "Messages:\n",
            DescItem::CustomFunc {
                path: Some("/status/conditions"),
                func: &get_message_str,
                default: "<No Messages>",
            },
        ),
    ];
    describe_object(&v, fields.into_iter())
}
