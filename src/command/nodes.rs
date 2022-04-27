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

use clap::{Arg, Command as ClapCommand};
use k8s_openapi::api::core::v1 as api;

use crate::{
    command::command_def::{exec_match, show_arg, sort_arg, start_clap, Cmd},
    command::{run_list_command, Extractor},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

lazy_static! {
    static ref NODE_EXTRACTORS: HashMap<String, Extractor<api::Node>> = {
        let mut m: HashMap<String, Extractor<api::Node>> = HashMap::new();
        m.insert("Container Runtime".to_owned(), node_container_runtime);
        m.insert("External Ip".to_owned(), node_external_ip);
        m.insert("Internal Ip".to_owned(), node_internal_ip);
        m.insert("Kernel Version".to_owned(), node_kernel_version);
        m.insert("Roles".to_owned(), node_roles);
        m.insert("Os Image".to_owned(), node_os_image);
        m.insert("State".to_owned(), node_state);
        m.insert("Version".to_owned(), node_version);
        m
    };
}

const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("state", "State"),
    ("roles", "Roles"),
    ("age", "Age"),
    ("version", "Version"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[
    ("internalip", "Internal Ip"),
    ("externalip", "External Ip"),
    ("osimage", "Os Image"),
    ("kernelversion", "Kernel Version"),
    ("containerruntime", "Container Runtime"),
    ("labels", "Labels"),
];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

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
        stat.addresses.as_ref().and_then(|addresses| {
            addresses
                .iter()
                .find(|&addr| addr.type_ == type_)
                .map(|addr| addr.address.as_str().into())
        })
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
    if let Some(labels) = &node.metadata.labels {
        for (k, v) in labels.iter() {
            if k.eq("kubernetes.io/role") {
                roles.push(v.as_str());
            } else if let Some(role) = k.strip_prefix("node-role.kubernetes.io/") {
                roles.push(role);
            }
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
    let readycond: Option<&api::NodeCondition> = node.status.as_ref().and_then(|stat| {
        stat.conditions
            .as_ref()
            .and_then(|conditions| conditions.iter().find(|c| c.type_ == "Ready"))
    });
    use crate::table::ColorType;
    let (state, fg) = if let Some(cond) = readycond {
        if cond.status == "True" {
            ("Ready", ColorType::Success)
        } else {
            ("Not Ready", ColorType::Danger)
        }
    } else {
        ("Unknown", ColorType::Warn)
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
    Some(CellSpec::with_colors(state, Some(fg.into()), None))
}

fn node_version(node: &api::Node) -> Option<CellSpec<'_>> {
    node.status.as_ref().and_then(|stat| {
        stat.node_info
            .as_ref()
            .map(|info| info.kubelet_version.as_str().into())
    })
}

list_command!(
    Nodes,
    "nodes",
    "Get nodes in the current context",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| {
        clap.arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("include labels in output (deprecated, use --show labels")
                .takes_value(false),
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::new("reverse")
                .short('R')
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        )
    },
    vec!["nodes"],
    noop_complete!(),
    [].into_iter(),
    |matches, env, writer| {
        let cols: Vec<&str> = COL_MAP.iter().map(|(_, col)| *col).collect();
        let (request, _response_body) = api::Node::list_node(Default::default())?;

        run_list_command(
            matches,
            env,
            writer,
            cols,
            request,
            COL_MAP,
            Some(EXTRA_COL_MAP),
            Some(&NODE_EXTRACTORS),
            node_to_kobj,
        )
    }
);
