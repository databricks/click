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

use std::array::IntoIter;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

lazy_static! {
    static ref SS_EXTRACTORS: HashMap<String, Extractor<apps_api::StatefulSet>> = {
        let mut m: HashMap<String, Extractor<apps_api::StatefulSet>> = HashMap::new();
        m.insert("Current".to_owned(), ss_current);
        m.insert("Containers".to_owned(), ss_containers);
        m.insert("Desired".to_owned(), ss_desired);
        m.insert("Images".to_owned(), ss_images);
        m.insert("Ready".to_owned(), ss_ready);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("desired", "Desired"),
    ("current", "Current"),
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

fn ss_to_kobj(statefulset: &apps_api::StatefulSet) -> KObj {
    let meta = &statefulset.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::StatefulSet,
    }
}

fn ss_containers(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset.spec.as_ref().and_then(|spec| {
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

fn ss_images(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset.spec.as_ref().and_then(|spec| {
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

fn ss_current(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset
        .status
        .as_ref()
        .map(|stat| match stat.current_replicas {
            Some(current) => current.into(),
            None => 0.into(),
        })
}

fn ss_desired(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset.status.as_ref().map(|stat| stat.replicas.into())
}

fn ss_ready(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset
        .status
        .as_ref()
        .map(|stat| match stat.ready_replicas {
            Some(ready) => ready.into(),
            None => 0.into(),
        })
}

list_command!(
    StatefulSets,
    "statefulsets",
    "Get statefulsets (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("Show statefulsets labels (deprecated, use --show labels)")
                .takes_value(false)
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter statefulsets by the specified regex")
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
    vec!["ss", "statefulsets"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => {
                apps_api::StatefulSet::list_namespaced_stateful_set(ns, Default::default())?
            }
            None => {
                apps_api::StatefulSet::list_stateful_set_for_all_namespaces(Default::default())?
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
            Some(&SS_EXTRACTORS),
            ss_to_kobj,
        )
    }
);
