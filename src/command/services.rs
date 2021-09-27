use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::core::v1 as api;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{keyval_string, run_list_command, show_arg, sort_arg, Extractor},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

use std::array::IntoIter;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

lazy_static! {
    static ref SERVICE_EXTRACTORS: HashMap<String, Extractor<api::Service>> = {
        let mut m: HashMap<String, Extractor<api::Service>> = HashMap::new();
        m.insert("Type".to_owned(), service_type);
        m.insert("Cluster IP".to_owned(), service_cluster_ip);
        m.insert("External IP".to_owned(), service_external_ip);
        m.insert("Port(s)".to_owned(), service_ports);
        m.insert("Selector".to_owned(), service_selector);
        m
    };
}

const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("type", "Type"),
    ("clusterip", "Cluster IP"),
    ("externalip", "External IP"),
    ("ports", "Port(s)"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[("selector", "Selector"), ("labels", "Labels")];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn service_to_kobj(service: &api::Service) -> KObj {
    let meta = &service.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::Service,
    }
}

fn service_type(service: &api::Service) -> Option<CellSpec<'_>> {
    service
        .spec
        .as_ref()
        .and_then(|spec| spec.type_.as_deref().map(|ip| ip.into()))
}

fn service_cluster_ip(service: &api::Service) -> Option<CellSpec<'_>> {
    service
        .spec
        .as_ref()
        .and_then(|spec| spec.cluster_ip.as_deref().map(|ip| ip.into()))
}

fn service_external_ip(service: &api::Service) -> Option<CellSpec<'_>> {
    service.status.as_ref().and_then(|stat| {
        stat.load_balancer.as_ref().map(|balancer| {
            if balancer.ingress.is_empty() {
                "<none>".into()
            } else {
                balancer
                    .ingress
                    .iter()
                    .map(|ingress| {
                        if let Some(hv) = ingress.hostname.as_deref() {
                            hv
                        } else if let Some(ipv) = ingress.ip.as_deref() {
                            ipv
                        } else {
                            ""
                        }
                    })
                    .collect::<Vec<&str>>()
                    .join(", ")
                    .into()
            }
        })
    })
}

fn service_ports(service: &api::Service) -> Option<CellSpec<'_>> {
    service.spec.as_ref().map(|spec| {
        let pvec: Vec<String> = spec
            .ports
            .iter()
            .map(|port| {
                let protocol = port.protocol.as_deref().unwrap_or("TCP");
                match port.node_port {
                    Some(np) => format!("{}:{}/{}", port.port, np, protocol),
                    None => format!("{}/{}", port.port, protocol),
                }
            })
            .collect();
        if pvec.is_empty() {
            "<none>".into()
        } else {
            pvec.join(", ").into()
        }
    })
}

fn service_selector(service: &api::Service) -> Option<CellSpec<'_>> {
    service
        .spec
        .as_ref()
        .map(|spec| keyval_string(&spec.selector).into())
}

list_command!(
    Services,
    "services",
    "Get services in the current context",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("labels")
                .short("L")
                .long("labels")
                .help("include labels in output (deprecated, use --show labels")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        )
    },
    vec!["services"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let cols: Vec<&str> = COL_MAP.iter().map(|(_, col)| *col).collect();
        let (request, _response_body) = match &env.namespace {
            Some(ns) => api::Service::list_namespaced_service(ns, Default::default()).unwrap(),
            None => api::Service::list_service_for_all_namespaces(Default::default()).unwrap(),
        };

        run_list_command(
            matches,
            env,
            writer,
            cols,
            request,
            COL_MAP,
            Some(EXTRA_COL_MAP),
            Some(&SERVICE_EXTRACTORS),
            service_to_kobj,
        );
    }
);
