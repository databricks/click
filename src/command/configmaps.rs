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

use std::array::IntoIter;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

lazy_static! {
    static ref CM_EXTRACTORS: HashMap<String, Extractor<api::ConfigMap>> = {
        let mut m: HashMap<String, Extractor<api::ConfigMap>> = HashMap::new();
        m.insert("Data".to_owned(), cm_data);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[("name", "Name"), ("data", "Data"), ("age", "Age")];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[("labels", "Labels")];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn cm_to_kobj(configmap: &api::ConfigMap) -> KObj {
    let meta = &configmap.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::ConfigMap,
    }
}

fn cm_data(configmap: &api::ConfigMap) -> Option<CellSpec<'_>> {
    Some(configmap.data.len().into())
}

list_command!(
    ConfigMaps,
    "configmaps",
    "Get configmaps (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("Show configmap labels (deprecated, use --show labels)")
                .takes_value(false)
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter confimaps by the specified regex")
                .takes_value(true)
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, None))
        .arg(
            Arg::new("reverse")
                .short('R')
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        ),
    vec!["cm", "configmaps"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => api::ConfigMap::list_namespaced_config_map(ns, Default::default())?,
            None => api::ConfigMap::list_config_map_for_all_namespaces(Default::default())?,
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
            Some(&CM_EXTRACTORS),
            cm_to_kobj,
        )
    }
);
