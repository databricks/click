use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::core::v1 as api;
use k8s_openapi::List;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{add_extra_cols, handle_list_result, show_arg, sort_arg, Extractor, SortFunc},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

use std::array::IntoIter;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{stderr, Write};

lazy_static! {
    static ref NODE_EXTRACTORS: HashMap<String, Extractor<api::Node>> = {
        let mut m: HashMap<String, Extractor<api::Node>> = HashMap::new();
        m.insert("Container Runtime".to_owned(), node_container_runtime);
        m.insert("External Ip".to_owned(), node_external_ip);
        m.insert("Internal Ip".to_owned(), node_internal_ip);
        m.insert("Kernel Version".to_owned(), node_kernel_version);
        m.insert("Labels".to_owned(), node_labels);
        m.insert("Roles".to_owned(), node_roles);
        m.insert("Os Image".to_owned(), node_os_image);
        m.insert("State".to_owned(), node_state);
        m.insert("Version".to_owned(), node_version);
        m
    };
    static ref EXTRA_COLS: Vec<(&'static str, &'static str)> = vec![
        ("internalip", "Internal Ip"),
        ("externalip", "External Ip"),
        ("osimage", "Os Image"),
        ("kernelversion", "Kernel Version"),
        ("containerruntime", "Container Runtime"),
        ("labels", "Labels"),
    ];
}

fn node_to_kobj(node: &api::Node) -> KObj {
    KObj {
        name: node
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<Unknown>".into()),
        namespace: None,
        typ: ObjType::Node,
    }
}

fn node_container_runtime(node: &api::Node) -> Option<CellSpec<'_>> {
    node.status.as_ref().and_then(|stat| {
        stat.node_info
            .as_ref()
            .map(|info| info.container_runtime_version.as_str().into())
    })
}

fn get_node_addr<'a>(node: &'a api::Node, type_: &str) -> Option<CellSpec<'a>> {
    node.status.as_ref().and_then(|stat| {
        stat.addresses
            .iter()
            .find(|&addr| addr.type_ == type_)
            .map(|addr| addr.address.as_str().into())
    })
}

fn node_external_ip(node: &api::Node) -> Option<CellSpec<'_>> {
    get_node_addr(node, "ExternalIP")
}

fn node_internal_ip(node: &api::Node) -> Option<CellSpec<'_>> {
    get_node_addr(node, "InternalIP")
}

fn node_kernel_version(node: &api::Node) -> Option<CellSpec<'_>> {
    node.status.as_ref().and_then(|stat| {
        stat.node_info
            .as_ref()
            .map(|info| info.kernel_version.as_str().into())
    })
}

fn node_labels(node: &api::Node) -> Option<CellSpec<'_>> {
    Some(crate::command::keyval_string(&node.metadata.labels).into())
}

fn node_os_image(node: &api::Node) -> Option<CellSpec<'_>> {
    node.status.as_ref().and_then(|stat| {
        stat.node_info
            .as_ref()
            .map(|info| info.os_image.as_str().into())
    })
}

// node roles are defined by labels that look like:
//   node-role.kubernetes.io/[role]=""
// or
//   kubernetes.io/role="[role]"
fn node_roles(node: &api::Node) -> Option<CellSpec<'_>> {
    let mut roles = vec![];
    for (k, v) in node.metadata.labels.iter() {
        if k.eq("kubernetes.io/role") {
            roles.push(v.as_str());
        } else if let Some(role) = k.strip_prefix("node-role.kubernetes.io/") {
            roles.push(role);
        }
    }
    if roles.is_empty() {
        Some("<none>".into())
    } else {
        Some(roles.join(", ").into())
    }
}

fn node_state<'a>(node: &'a api::Node) -> Option<CellSpec<'a>> {
    // scope borrows
    let readycond: Option<&api::NodeCondition> = node
        .status
        .as_ref()
        .and_then(|stat| stat.conditions.iter().find(|c| c.type_ == "Ready"));
    let (state, state_style) = if let Some(cond) = readycond {
        if cond.status == "True" {
            ("Ready", "Fg")
        } else {
            ("Not Ready", "Fr")
        }
    } else {
        ("Unknown", "Fy")
    };

    let state: Cow<'a, str> = match node.spec.as_ref().and_then(|spec| spec.unschedulable) {
        Some(unsched) => {
            if unsched {
                format!("{}\nSchedulingDisabled", state).into()
            } else {
                state.into()
            }
        }
        None => state.into(),
    };
    Some(CellSpec::with_style(state, state_style))
}

fn node_version(node: &api::Node) -> Option<CellSpec<'_>> {
    node.status.as_ref().and_then(|stat| {
        stat.node_info
            .as_ref()
            .map(|info| info.kubelet_version.as_str().into())
    })
}

command!(
    Nodes,
    "nodes",
    "Get nodes in the current context",
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
        .arg(show_arg(
            &EXTRA_COLS
                .iter()
                .map(|(flag, _)| *flag)
                .collect::<Vec<&str>>(),
            true,
        ))
        .arg(sort_arg(
            &["name", "state", "age", "roles", "version"],
            Some(
                &EXTRA_COLS
                    .iter()
                    .map(|(flag, _)| *flag)
                    .collect::<Vec<&str>>(),
            ),
        ))
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        )
    },
    vec!["nodes"],
    noop_complete!(),
    IntoIter::new([(
        "sort".to_string(),
        completer::node_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
    )])
    .collect(),
    |matches, env, writer| {
        let regex = match crate::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let (request, _response_body) = api::Node::list_node(Default::default()).unwrap();
        let node_list_opt: Option<List<api::Node>> =
            env.run_on_context(|c| c.execute_list(request));
        let mut cols = vec!["Name", "State", "Roles", "Age", "Version"];

        let mut flags: Vec<&str> = match matches.values_of("show") {
            Some(v) => v.collect(),
            None => vec![],
        };

        let sort = matches
            .value_of("sort")
            .map(|s| match s.to_lowercase().as_str() {
                "age" => {
                    let sf = crate::command::PreExtractSort {
                        cmp: crate::command::age_cmp,
                    };
                    SortFunc::Pre(sf)
                }
                "name" => SortFunc::Post("Name"),
                "labels" => {
                    flags.push("labels");
                    SortFunc::Post("Labels")
                }
                "state" => SortFunc::Post("State"),
                "roles" => SortFunc::Post("Roles"),
                "version" => SortFunc::Post("Version"),
                other => {
                    let mut func = None;
                    for (flag, col) in EXTRA_COLS.iter() {
                        if flag.eq(&other) {
                            flags.push(flag);
                            func = Some(SortFunc::Post(col));
                        }
                    }
                    match func {
                        Some(f) => f,
                        None => panic!("Shouldn't be allowed to ask to sort by: {}", other),
                    }
                }
            });

        add_extra_cols(&mut cols, matches.is_present("labels"), flags, &EXTRA_COLS);

        handle_list_result(
            env,
            writer,
            cols,
            node_list_opt,
            Some(&NODE_EXTRACTORS),
            regex,
            sort,
            matches.is_present("reverse"),
            node_to_kobj,
        );
    }
);
