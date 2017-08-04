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

use values::{val_str, val_u64};

use ansi_term::Colour::{Green};
use chrono::DateTime;
use chrono::offset::local::Local;
use chrono::offset::utc::UTC;
use serde_json::Value;

use std::str::FromStr;

/// Utility function for describe to print out value
pub fn describe_format_pod(v: Value) -> String {
    let metadata = v.get("metadata").unwrap();
    let spec = v.get("spec").unwrap();
    let status = v.get("status").unwrap();
    let created: DateTime<UTC> =
        DateTime::from_str(
            val_str("/creationTimestamp", metadata, "<No CreationTime>").as_str()
        ).unwrap();

    let volumes = spec.get("volumes");
    let volstr = if let Some(vols) = volumes {
        get_volume_str(vols)
    } else {
        "No Volumes".to_owned()
    };

    format!(
        "Name:\t\t{}\n\
Namespace:\t{}
Node:\t\t{}
IP:\t\t{}
Created at:\t{} ({})
Status:\t\t{}
{}
{}
{}", // TODO: Controllers
        val_str("/name", metadata, "<No Name>"),
        val_str("/namespace", metadata, "<No Namespace>"),
        val_str("/nodeName", spec, "<No NodeName"),
        val_str("/podIP", status, "<No PodIP>"),
        created,
        created.with_timezone(&Local),
        Green.paint(val_str("/phase", status, "<No Phase>")),
        get_keyval_str(metadata, "labels", "Labels:\t"),
        get_keyval_str(metadata, "annotations", "Annotations:"),
        volstr,
    )
}

/// Utility function for describe to print out value
pub fn describe_format_node(v: Value) -> String {
    let metadata = v.get("metadata").unwrap();
    let spec = v.get("spec").unwrap();
    let created: DateTime<UTC> =
        DateTime::from_str(
            val_str("/creationTimestamp", metadata, "<No CreationTime>").as_str()
        ).unwrap();

    format!(
        "Name:\t\t{}
{}
Created at:\t{} ({})
ProviderId:\t{}",
        val_str("/name", metadata, "<No Name>"),
        get_keyval_str(metadata, "labels", "Labels"),
        created,
        created.with_timezone(&Local),
        val_str("/providerID", spec, "<No ProviderID>"),
    )
}

/// Utility function for describe to print service info
pub fn describe_format_service(v: Value, endpoint_val: Option<Value>) -> String {
    match v.get("metadata") {
        Some(metadata) => {
            format!(
                "Name:\t\t{}
Namespace:\t{}
{}
{}
{}
Type:\t\t{}
IP:\t\t{}
LoadBalIngress:\t{}
{}SessionAffnity:\t{}",  // no newline after ports as it ends up with an extra newline

                val_str("/name", metadata, "<No Name>"),
                val_str("/namespace", metadata, "<No Namespace>"),
                get_keyval_str(metadata, "labels", "Labels:\t"),
                get_keyval_str(metadata, "annotations", "Annotations:"),
                get_keyval_str_opt(v.pointer("/spec"), "selector", "Selector:"),
                val_str("/spec/type", &v, "<No Type>"),
                val_str("/spec/clusterIP", &v, "<No IP>"),
                val_str("/status/loadBalancer/ingress/0/hostname", &v, "<No Ingress>"),
                get_ports_str(v.pointer("/spec/ports"), endpoint_val),
                val_str("/spec/sessionAffinity", &v, "<none>"),
            )
        },
        None => {
            "Response contains no metadata element, cannot describe (try -j)".to_owned()
        }
    }
}


/// small wrapper to make v.pointer calls as args to get_keyval_str easier
fn get_keyval_str_opt(v: Option<&Value>, parent: &str, title: &str) -> String {
    match v {
        Some(val) => get_keyval_str(val, parent, title),
        None => "<Unknown>".to_owned(),
    }
}

/// get key/vals out of metadata
fn get_keyval_str(v: &Value, parent: &str, title: &str) -> String {
    let mut outstr = title.to_owned();
    match v.get(parent) {
        Some(p) => {
            if let Some(keyvals) = p.as_object() {
                let mut first = true;
                for key in keyvals.keys() {
                    if !first {
                        outstr.push('\n');
                        outstr.push('\t');
                    }
                    first = false;
                    outstr.push('\t');
                    outstr.push_str(key);
                    outstr.push('=');
                    outstr.push_str(keyvals.get(key).unwrap().as_str().unwrap());
                }
            }
        },
        None => {
            outstr.push_str("\t<none>");
        }
    }
    outstr
}

/// Get ports info out of ports array
fn get_ports_str(v: Option<&Value>, endpoint_val: Option<Value>) -> String {
    if v.is_none() {
        return "Ports:\t<none>".to_owned();
    }
    let mut buf = String::new();
    buf.push_str("Ports:\n");
    match v.unwrap().as_array() { // safe unwrap, checked above
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
                        ep.pointer("/subsets").map(|s| s.as_array().map(|subsets| {
                            for subset in subsets.iter() {
                                // see if this subset has this port by checking if any port in the ports
                                // array has the same port number
                                let contains =
                                    subset.pointer("/ports").map(|p| p.as_array().map(|ports_array| {
                                        let mut c = false;
                                        for port in ports_array.iter() {
                                            if port_num == val_u64("/port", port, 0) {
                                                c = true;
                                            }
                                        }
                                        c
                                    }).unwrap_or(false)).unwrap_or(false);
                                if contains {
                                    // we do have this port, need to add all addresses as endpoints
                                    found_one = true;
                                    let port_num = val_u64("/targetPort", port, 0);
                                    subset.pointer("/addresses").map(|a| a.as_array().map(|addr_array| {
                                        let mut first = true;
                                        for addr in addr_array.iter() {
                                            if first {
                                                first = false;
                                            } else {
                                                epbuf.push_str(", ");
                                            }
                                            epbuf.push_str(format!("{}:{}", val_str("/ip", addr, "<No IP>"), port_num).as_str());
                                        }
                                    }));
                                }
                            }
                        }));
                        if !found_one {
                            epbuf.push_str("<none>");
                        }
                        epbuf
                    },
                    None => {
                        "<No Endpoints>".to_owned()
                    }
                };
                buf.push_str(format!("  Port:\t\t{} {}/{}\n",
                                     name,
                                     port_num,
                                     proto
                ).as_str());
                buf.push_str(format!("  NodePort:\t{} {}/{}\n",
                                     val_str("/name", port, "<No Name>"),
                                     val_u64("/nodePort", port, 0),
                                     proto
                ).as_str());
                buf.push_str(endpoints.as_str());
                buf.push('\n');
                buf.push('\n');
            }
        }
        None => {
            buf.push_str("<none>")
        }
    }
    buf
}

/// Get volume info out of volume array
fn get_volume_str(v: &Value) -> String {
    let mut buf = String::new();
    buf.push_str("Volumes:\n");
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
                    format!("    SecretName:\t{}\n",
                            val_str("/secretName", secret, "<No SecretName>")).as_str(),
                );
            }
            if let Some(aws) = vol.get("awsElasticBlockStore") {
                buf.push_str(
                    "    Type:\tAWS Block Store (An AWS Disk resource exposed to the pod)\n",
                );
                buf.push_str(
                    format!("    VolumeId:\t{}\n", val_str("/volumeID", aws, "<No VolumeID>")).as_str(),
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
    buf
}
