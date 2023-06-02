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
use crate::values::{val_str, val_str_opt, val_u64};

use base64::engine::{general_purpose::STANDARD, Engine};
use chrono::offset::Local;
use chrono::offset::Utc;
use chrono::DateTime;
use crossterm::style::Stylize;
use k8s_openapi::api::{apps::v1 as api_apps, core::v1 as api};
use serde_json::Value;

use std::borrow::Cow;
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
}

/// get key/vals out of a value
/// If secret_vals is true, the actual vals are hidden and we show only the size of the value
fn keyval_str<'a>(v: &'a Value, parent: &str, secret_vals: bool) -> Cow<'a, str> {
    match v.pointer(parent) {
        Some(p) => {
            if let Some(keyvals) = p.as_object() {
                let iter = keyvals.into_iter().map(|(key, val)| {
                    let is_service_token = if secret_vals && key == "token" {
                        let typ = v.pointer("/type").and_then(|t| t.as_str()).unwrap_or("");
                        typ == "kubernetes.io/service-account-token"
                    } else {
                        false
                    };

                    let computed_val: Cow<'a, str> = if is_service_token {
                        match STANDARD.decode(val.as_str().unwrap()) {
                            Ok(dec) => str::from_utf8(&dec[..])
                                .map(|s| s.to_string())
                                .unwrap_or_else(|_e| "Invalid utf-8 data".to_string())
                                .into(),
                            Err(_) => "Could not decode secret".into(),
                        }
                    } else if secret_vals {
                        match STANDARD.decode(val.as_str().unwrap()) {
                            Ok(dec) => format!("{} bytes", dec.len()).into(),
                            Err(_) => "Could not decode secret".into(),
                        }
                    } else {
                        val.as_str().unwrap_or("<unknown>").into()
                    };

                    (key.as_str(), computed_val)
                });
                crate::command::keyval_string(iter, Some(&super::DESCRIBE_SKIP_KEYS)).into()
            } else {
                "<none>".into()
            }
        }
        None => "<none>".into(),
    }
}

/// Generic describe function
/// TODO: Document
pub fn describe_object<'a, I>(v: &Value, fields: I, table: &mut comfy_table::Table)
where
    I: Iterator<Item = (&'a str, DescItem<'a>)>,
{
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
        };
        table.add_row(vec![title, val.as_ref()]);
    }
}

/// Utility function for describe to print out value
pub fn describe_format_pod(
    pod: &api::Pod,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let v = serde_json::value::to_value(pod).unwrap();
    let fields = vec![
        (
            "Name:",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Namespace:",
            DescItem::MetadataValStr {
                path: "/namespace",
                default: "<No Name>",
            },
        ),
        (
            "Node:",
            DescItem::ValStr {
                path: "/spec/nodeName",
                default: "<No NodeName>",
            },
        ),
        (
            "IP:",
            DescItem::ValStr {
                path: "/status/podIP",
                default: "<No PodIP>",
            },
        ),
        ("Created at:", DescItem::ObjectCreated),
        (
            "Status:",
            DescItem::CustomFunc {
                path: None,
                func: &pod_phase,
                default: "<No Phase>",
            },
        ),
        (
            "Labels:",
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
            "Volumes:",
            DescItem::CustomFunc {
                path: Some("/spec/volumes"),
                func: &get_volume_str,
                default: "<No Volumes>",
            },
        ),
    ];
    describe_object(&v, fields.into_iter(), table);
    Ok(())
}

/// Check if value has read only set
fn get_read_only(v: &Value) -> &'static str {
    if let Some(read_only) = v.get("readOnly") {
        if read_only.as_bool().unwrap() {
            "  Read-Only: True\n"
        } else {
            "  Read-Only: False\n"
        }
    } else {
        "  Read-Only: False\n"
    }
}

/// Add descriptions of downwardapi items to buf
fn add_downward_items(items: &[Value], buf: &mut String) {
    let mut first = true;
    for item in items.iter() {
        if let Some(fr) = item.get("fieldRef") {
            if first {
                first = false;
            } else {
                buf.push('\n');
            }
            buf.push_str("    ");
            if let Some(path) = fr.get("fieldPath") {
                buf.push_str(path.as_str().unwrap_or("<unknown path>"));
            } else {
                buf.push_str("<unknown path>");
            }
            buf.push_str(" -> ");
            buf.push_str(
                item.get("path")
                    .and_then(|s| s.as_str())
                    .unwrap_or("<unknown path>"),
            );
        }
        if let Some(resource_field_ref) = item.get("resource_field_ref") {
            if first {
                first = false;
            } else {
                buf.push('\n');
            }
            buf.push_str("    ");
            if let Some(resource) = resource_field_ref.get("resource") {
                buf.push_str(resource.as_str().unwrap_or("<unknown resource>"));
            } else {
                buf.push_str("<unknown resource>");
            }
            buf.push_str(" -> ");
            buf.push_str(
                item.get("path")
                    .and_then(|s| s.as_str())
                    .unwrap_or("<unknown path>"),
            );
            buf.push_str(" (container: ");
            buf.push_str(
                resource_field_ref
                    .get("container")
                    .and_then(|s| s.as_str())
                    .unwrap_or("<unknown container>"),
            );
            buf.push_str(", divisor: ");
            buf.push_str(
                resource_field_ref
                    .get("divisor")
                    .and_then(|s| s.as_str())
                    .unwrap_or("<unknown divisor>"),
            );
            buf.push(')');
        }
    }
    buf.push('\n');
}

/// Get volume info out of volume array
fn get_volume_str(v: &Value) -> Cow<str> {
    let mut buf = String::new();
    if let Some(vol_arry) = v.as_array() {
        for vol in vol_arry.iter() {
            buf.push_str(format!("{}:\n", val_str("/name", vol, "<No Name>")).as_str());
            if vol.get("emptyDir").is_some() {
                buf.push_str(
                    "  Type: EmptyDir (a temporary directory that shares a pod's lifetime)\n",
                )
            }
            if let Some(conf_map) = vol.get("configMap") {
                buf.push_str("  Type: ConfigMap (a volume populated by a ConfigMap)\n");
                buf.push_str(
                    format!("  Name: {}\n", val_str("/name", conf_map, "<No Name>")).as_str(),
                );
            }
            if let Some(secret) = vol.get("secret") {
                buf.push_str("  Type:       Secret (a volume populated by a Secret)\n");
                buf.push_str(
                    format!(
                        "  SecretName: {}\n",
                        val_str("/secretName", secret, "<No SecretName>")
                    )
                    .as_str(),
                );
            }
            if let Some(aws) = vol.get("awsElasticBlockStore") {
                buf.push_str(
                    "  Type:      AWS Block Store (An AWS Disk resource exposed to the pod)\n",
                );
                buf.push_str(
                    format!(
                        "  VolumeId: {}\n",
                        val_str("/volumeID", aws, "<No VolumeID>")
                    )
                    .as_str(),
                );
                buf.push_str(
                    format!("  FSType: {}\n", val_str("/fsType", aws, "<No FsType>")).as_str(),
                );
                let mut pnum = 0;
                if let Some(part) = aws.get("partition") {
                    if let Some(p) = part.as_u64() {
                        pnum = p;
                    }
                }
                buf.push_str(format!("  Partition#: {pnum}\n").as_str());
                buf.push_str(get_read_only(aws));
            }
            if let Some(pvc) = vol.get("persistentVolumeClaim") {
                buf.push_str("  Type:      PersistentVolumeClaim (a reference to a PersistentVolumeClaim in the same namespace)\n");
                buf.push_str(
                    format!("  ClaimName: {}\n", val_str("/claimName", pvc, "<No Name>")).as_str(),
                );
                buf.push_str(get_read_only(pvc));
            }
            if let Some(dapi) = vol.get("downwardAPI") {
                buf.push_str("  Type: DownwardAPI (a volume populated by information about the pod)\n  Items:\n");
                if let Some(items_val) = dapi.get("items") {
                    if let Some(items) = items_val.as_array() {
                        add_downward_items(items, &mut buf);
                    }
                }
            }
        }
    }
    buf.into()
}

fn pod_phase(v: &Value) -> Cow<str> {
    // TODO: How to get an env in here for the colors
    let phase_str = val_str("/status/phase", v, "<No Phase>");
    match &*phase_str {
        "Pending" | "Unknown" => phase_str.yellow().to_string().into(),
        "Running" | "Succeeded" => phase_str.green().to_string().into(),
        "Failed" => phase_str.red().to_string().into(),
        _ => phase_str.yellow().to_string().into(),
    }
}

/// Utility function for describe to print out value
pub fn describe_format_node(
    node: &api::Node,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let v = serde_json::value::to_value(node).unwrap();
    let fields = vec![
        (
            "Name:",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Labels:",
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
        ("Created at:", DescItem::ObjectCreated),
        (
            "Provider Id:",
            DescItem::ValStr {
                path: "/spec/providerID",
                default: "<No Provider Id>",
            },
        ),
        (
            "External URL:",
            DescItem::CustomFunc {
                path: None,
                func: &node_access_url,
                default: "<N/A>",
            },
        ),
        (
            "System Info:",
            DescItem::KeyValStr {
                parent: "/status/nodeInfo",
                secret_vals: false,
            },
        ),
    ];
    describe_object(&v, fields.into_iter(), table);
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
                        format!("Unexpected ip format: {ip}").into()
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
pub fn describe_format_secret(
    secret: &api::Secret,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let v = serde_json::value::to_value(secret).unwrap();
    let fields = vec![
        (
            "Name:",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Namespace:",
            DescItem::MetadataValStr {
                path: "/namespace",
                default: "<No Name>",
            },
        ),
        (
            "Labels:",
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
            "Type:",
            DescItem::ValStr {
                path: "/type",
                default: "<No Type>",
            },
        ),
        (
            "Data:",
            DescItem::KeyValStr {
                parent: "/data",
                secret_vals: true,
            },
        ),
    ];
    describe_object(&v, fields.into_iter(), table);
    Ok(())
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
            buf.push_str(format!("  Message: {msg}\n").as_str());
        }
    }
    buf.into()
}

/// Utility function to describe a deployment
pub fn describe_format_deployment(
    deployment: &api_apps::Deployment,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let v = serde_json::value::to_value(deployment).unwrap();
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
    describe_object(&v, fields.into_iter(), table);
    Ok(())
}

/// Utility function to describe a rollout
#[cfg(feature = "argorollouts")]
use crate::command::rollouts;
#[cfg(feature = "argorollouts")]
pub fn describe_format_rollout(
    rollout: &rollouts::RolloutValue,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let v = serde_json::value::to_value(rollout).unwrap();
    let fields = vec![
        (
            "Name:",
            DescItem::MetadataValStr {
                path: "/name",
                default: "<No Name>",
            },
        ),
        (
            "Namespace:",
            DescItem::MetadataValStr {
                path: "/namespace",
                default: "<No Name>",
            },
        ),
        ("Created at:", DescItem::ObjectCreated),
        (
            "Generation:",
            DescItem::Valu64 {
                path: "/metadata/generation",
                default: 0,
            },
        ),
        (
            "Labels:",
            DescItem::KeyValStr {
                parent: "/metadata/labels",
                secret_vals: false,
            },
        ),
        (
            "Desired Replicas:",
            DescItem::Valu64 {
                path: "/spec/replicas",
                default: 0,
            },
        ),
        (
            "Current Replicas:",
            DescItem::Valu64 {
                path: "/status/replicas",
                default: 0,
            },
        ),
        (
            "Up To Date Replicas:",
            DescItem::Valu64 {
                path: "/status/updatedReplicas",
                default: 0,
            },
        ),
        (
            "Available Replicas:",
            DescItem::Valu64 {
                path: "/status/availableReplicas",
                default: 0,
            },
        ),
        (
            "Containers:",
            DescItem::CustomFunc {
                path: Some("/spec/template/spec/containers"),
                func: &get_container_str,
                default: "<No Containers>",
            },
        ),
        (
            "Messages:",
            DescItem::CustomFunc {
                path: Some("/status/conditions"),
                func: &get_message_str,
                default: "<No Messages>",
            },
        ),
    ];
    describe_object(&v, fields.into_iter(), table);
    Ok(())
}
