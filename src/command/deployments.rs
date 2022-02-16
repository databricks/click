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
    static ref DEPLOYMENT_EXTRACTORS: HashMap<String, Extractor<apps_api::Deployment>> = {
        let mut m: HashMap<String, Extractor<apps_api::Deployment>> = HashMap::new();
        m.insert("Containers".to_owned(), deployment_containers);
        m.insert("Images".to_owned(), deployment_images);
        m.insert("Ready".to_owned(), deployment_ready);
        m.insert("Desired".to_owned(), deployment_desired);
        m.insert("Up To Date".to_owned(), deployment_uptodate);
        m.insert("Available".to_owned(), deployment_available);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("ready", "Ready"),
    ("desired", "Desired"),
    ("uptodate", "Up To Date"),
    ("available", "Available"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[
    ("containers", "Containers"),
    ("images", "Images"),
    ("namespace", "Namespace"),
];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn deployment_to_kobj(deployment: &apps_api::Deployment) -> KObj {
    let meta = &deployment.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::Deployment,
    }
}

fn deployment_containers(deployment: &apps_api::Deployment) -> Option<CellSpec<'_>> {
    deployment.spec.as_ref().and_then(|spec| {
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

fn deployment_images(deployment: &apps_api::Deployment) -> Option<CellSpec<'_>> {
    deployment.spec.as_ref().and_then(|spec| {
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

fn deployment_desired(deployment: &apps_api::Deployment) -> Option<CellSpec<'_>> {
    deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas.as_ref().map(|r| (*r).into()))
}

fn deployment_available(deployment: &apps_api::Deployment) -> Option<CellSpec<'_>> {
    deployment
        .status
        .as_ref()
        .map(|stat| match stat.available_replicas {
            Some(avail) => avail.into(),
            None => 0.into(),
        })
}

fn deployment_ready(deployment: &apps_api::Deployment) -> Option<CellSpec<'_>> {
    deployment
        .status
        .as_ref()
        .map(|stat| match stat.ready_replicas {
            Some(ready) => ready.into(),
            None => 0.into(),
        })
}

fn deployment_uptodate(deployment: &apps_api::Deployment) -> Option<CellSpec<'_>> {
    deployment
        .status
        .as_ref()
        .map(|stat| match stat.updated_replicas {
            Some(updated) => updated.into(),
            None => 0.into(),
        })
}

list_command!(
    Deployments,
    "deployments",
    "Get deployments (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("show_label")
                .short('L')
                .long("labels")
                .help("Show deployments labels (deprecated, use --show labels)")
                .takes_value(true)
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter deployments by the specified regex")
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
    vec!["deps", "deployments"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => apps_api::Deployment::list_namespaced_deployment(ns, Default::default())?,
            None => apps_api::Deployment::list_deployment_for_all_namespaces(Default::default())?,
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
            Some(&DEPLOYMENT_EXTRACTORS),
            deployment_to_kobj,
        )
    }
);
