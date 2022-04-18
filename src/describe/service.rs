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

// service is a bit more complex, so handle it here

use crate::{
    command::keyval_string,
    env::Env,
    error::ClickError,
    output::ClickWriter,
    values::{val_str, val_u64},
};

use clap::ArgMatches;
use k8s_openapi::api::core::v1 as api;
use serde_json::Value;
use std::{borrow::Cow, io::Write, str::FromStr};

pub fn service_describe(
    name: &str,
    namespace: &str,
    matches: &ArgMatches,
    env: &Env,
    writer: &mut ClickWriter,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let (request, _) =
        api::Endpoints::read_namespaced_endpoints(name, namespace, Default::default()).unwrap();
    let epval = match env.run_on_context(|c| c.read(request)).unwrap() {
        api::ReadNamespacedEndpointsResponse::Ok(resp) => serde_json::value::to_value(&resp).ok(),
        _ => {
            clickwriteln!(writer, "Error fetching endpoints");
            None
        }
    };

    let (request, _) =
        api::Service::read_namespaced_service(name, namespace, Default::default()).unwrap();
    match env.run_on_context(|c| c.read(request)).unwrap() {
        api::ReadNamespacedServiceResponse::Ok(service) => {
            if !super::maybe_full_describe_output(matches, &service, writer) {
                super::describe_metadata(&service, writer, table)?;
                let val = serde_json::value::to_value(&service).unwrap();
                describe_format_service(&service, val, epval, writer, table);
            }
        }
        _ => {
            clickwriteln!(writer, "Invalid response trying to read service info");
        }
    }
    Ok(())
}

/// Utility function for describe to print service info
fn describe_format_service(
    service: &api::Service,
    v: Value,
    endpoint_val: Option<Value>,
    writer: &mut ClickWriter,
    table: &mut comfy_table::Table,
) {
    let port_str = get_ports_str(v.pointer("/spec/ports"), endpoint_val);
    table.add_row(vec![
        "Selector:",
        service
            .spec
            .as_ref()
            .map(|spec| { keyval_string(&spec.selector, None, None) })
            .unwrap_or_else(|| "<none>".to_string()).as_str()
    ]);
    table.add_row(vec![
        "Type:",
        service
            .spec
            .as_ref()
            .and_then(|spec| { spec.type_.as_deref() })
            .unwrap_or("<none>")
    ]);
    table.add_row(vec![
        "IP:",
        service
            .spec
            .as_ref()
            .and_then(|spec| { spec.cluster_ip.as_deref() })
            .unwrap_or("<none>")
    ]);

    let ingress = match service
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
    {
        Some(load_bal) => {
            let mut buf = String::new();
            if load_bal.ingress.is_empty() {
                buf.push_str("<none>");
            } else {
                for ingress in load_bal.ingress.iter() {
                    let istr = ingress
                        .hostname
                        .as_deref()
                        .unwrap_or_else(|| ingress.ip.as_deref().unwrap_or("<unknown>"));
                    buf.push_str(istr);
                }
            }
            buf
        }
        None => "<none>".to_string(),
    };
    table.add_row(vec!["LoadBalIngress:", ingress.as_str()]);
    table.add_row(vec![
        "Session Affinity:",
        service
            .spec
            .as_ref()
            .and_then(|spec| { spec.session_affinity.as_deref() })
            .unwrap_or("<none>")
    ]);
    table.add_row(vec![
        "External Traffic Policy:",
        service
            .spec
            .as_ref()
            .and_then(|spec| { spec.external_traffic_policy.as_deref() })
            .unwrap_or("<none>")
    ]);
    table.add_row(vec![
        "Load Balancer Source Ranges:",
        service
            .spec
            .as_ref()
            .and_then(|spec| {
                if spec.load_balancer_source_ranges.is_empty() {
                    None
                } else {
                    Some(spec.load_balancer_source_ranges.join(", "))
                }
            })
            .unwrap_or_else(|| "<none>".to_string()).as_str()
    ]);
    table.add_row(vec![
        "Ports:", port_str.as_ref()
    ]);
}

/// Get ports info out of ports array
fn get_ports_str(v: Option<&Value>, endpoint_val: Option<Value>) -> Cow<str> {
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
                        let mut epbuf = String::from_str("Endpoints:  ").unwrap();
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
                                                        format!(
                                                            "{}:{}",
                                                            val_str("/ip", addr, "<No IP>"),
                                                            port_num
                                                        )
                                                        .as_str(),
                                                    );
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
                        epbuf.push('\n');
                        epbuf
                    }
                    None => "<No Endpoints>\n".to_owned(),
                };
                buf.push_str(format!("Port:  {} {}/{}\n", name, port_num, proto).as_str());
                buf.push_str(
                    format!(
                        "NodePort:  {} {}/{}\n",
                        val_str("/name", port, "<No Name>"),
                        val_u64("/nodePort", port, 0),
                        proto
                    )
                    .as_str(),
                );
                buf.push_str(endpoints.as_str());
            }
        }
        None => buf.push_str("<none>"),
    }
    if let Some(last) = buf.chars().last() {
        if last == '\n' {
            buf.pop();
        }
    }
    buf.into()
}
