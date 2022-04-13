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

use ansi_term::Colour::Yellow;
use clap::{Arg, Command as ClapCommand};
use k8s_openapi::api::apps::v1 as apps_api;

use crate::{
    command::command_def::{exec_match, show_arg, sort_arg, start_clap, Cmd},
    command::{run_list_command, Extractor},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

lazy_static! {
    static ref DS_EXTRACTORS: HashMap<String, Extractor<apps_api::DaemonSet>> = {
        let mut m: HashMap<String, Extractor<apps_api::DaemonSet>> = HashMap::new();
        m.insert("Available".to_owned(), ds_available);
        m.insert("Current".to_owned(), ds_current);
        m.insert("Containers".to_owned(), ds_containers);
        m.insert("Desired".to_owned(), ds_desired);
        m.insert("Images".to_owned(), ds_images);
        m.insert("Ready".to_owned(), ds_ready);
        m.insert("Up-To-Date".to_owned(), ds_up_to_date);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("desired", "Desired"),
    ("current", "Current"),
    ("ready", "Ready"),
    ("uptodate", "Up-To-Date"),
    ("available", "Available"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[
    ("containers", "Containers"),
    ("images", "Images"),
    ("labels", "Labels"),
    ("namespace", "Namespace"),
];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn ds_to_kobj(daemonset: &apps_api::DaemonSet) -> KObj {
    let meta = &daemonset.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::DaemonSet,
    }
}

fn ds_containers(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.spec.as_ref().and_then(|spec| {
        spec.template.spec.as_ref().map(|pod_spec| {
            let names: Vec<&str> = pod_spec
                .containers
                .iter()
                .map(|cont| cont.name.as_str())
                .collect();
            names.join(", ").into()
        })
    })
}

fn ds_images(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.spec.as_ref().and_then(|spec| {
        spec.template.spec.as_ref().map(|pod_spec| {
            let names: Vec<&str> = pod_spec
                .containers
                .iter()
                .map(|cont| cont.image.as_deref().unwrap_or("<unknown>"))
                .collect();
            names.join(", ").into()
        })
    })
}

fn ds_available(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.status.as_ref().and_then(|stat| {
        stat.number_available.map(|num| num.into())
    })
}

fn ds_current(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.status.as_ref().map(|status| status.current_number_scheduled.into())
}

fn ds_desired(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.status.as_ref().map(|status| status.desired_number_scheduled.into())
}

fn ds_ready(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.status.as_ref().map(|stat| stat.number_ready.into())
}

fn ds_up_to_date(daemonset: &apps_api::DaemonSet) -> Option<CellSpec<'_>> {
    daemonset.status.as_ref().and_then(|stat| {
        stat.updated_number_scheduled.map(|num| num.into())
    })
}

list_command!(
    DaemonSets,
    "daemonsets",
    "Get daemonsets (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("Show daemonsets labels (deprecated, use --show labels)")
                .takes_value(false)
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter daemonsets by the specified regex")
                .takes_value(true)
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::new("reverse")
                .short('R')
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        ),
    vec!["ds", "daemonsets"],
    noop_complete!(),
    [].into_iter(),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => {
                apps_api::DaemonSet::list_namespaced_daemon_set(ns, Default::default())?
            }
            None => {
                apps_api::DaemonSet::list_daemon_set_for_all_namespaces(Default::default())?
            }
        };
        let cols: Vec<&str> = COL_MAP.iter().map(|(_, col)| *col).collect();

        run_list_command(
            matches,
            env,
            writer,
            cols,
            request,
            COL_MAP,
            Some(EXTRA_COL_MAP),
            Some(&DS_EXTRACTORS),
            ds_to_kobj,
        )
    }
);
