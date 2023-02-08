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
use k8s_openapi::api::batch::v1 as batch_api;

use crate::{
    command::command_def::{exec_match, show_arg, sort_arg, start_clap, Cmd},
    command::{keyval_string, run_list_command, time_since, Extractor},
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
    static ref JOB_EXTRACTORS: HashMap<String, Extractor<batch_api::Job>> = {
        let mut m: HashMap<String, Extractor<batch_api::Job>> = HashMap::new();
        m.insert("Completions".to_owned(), job_completions);
        m.insert("Duration".to_owned(), job_duration);
        m.insert("Containers".to_owned(), job_containers);
        m.insert("Images".to_owned(), job_images);
        m.insert("Selector".to_owned(), job_selector);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("completions", "Completions"),
    ("duration", "Duration"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[
    ("containers", "Containers"),
    ("images", "Images"),
    ("selector", "Selector"),
    ("labels", "Labels"),
];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn job_to_kobj(job: &batch_api::Job) -> KObj {
    let meta = &job.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::StatefulSet,
    }
}

fn job_completions(job: &batch_api::Job) -> Option<CellSpec<'_>> {
    let completions = job.spec.as_ref().and_then(|s| s.completions).unwrap_or(0);
    let succeeded = job.status.as_ref().and_then(|s| s.succeeded).unwrap_or(0);
    Some(format!("{succeeded}/{completions}").into())
}

fn job_duration(job: &batch_api::Job) -> Option<CellSpec<'_>> {
    let stat = job.status.as_ref();
    match stat.and_then(|s| s.start_time.as_ref()) {
        Some(start) => {
            let end = stat.and_then(|s| s.completion_time.as_ref()).or_else(|| {
                stat.and_then(|s| {
                    s.conditions
                        .as_ref()
                        .and_then(|conditions| {
                            conditions.iter().find(|cond| {
                                // we assume a succeeded job has a completion_time so here,
                                // find the "failed" condition and find when it happened
                                cond.type_ == "Failed" || cond.status == "True"
                            })
                        })
                        .and_then(|cond| cond.last_transition_time.as_ref())
                })
            });
            match end {
                Some(end) => {
                    let diff = end.0.signed_duration_since(start.0);
                    Some(diff.into())
                }
                None => Some(time_since(start.0).into()),
            }
        }
        None => Some("Unknown".into()),
    }
}

fn job_containers(job: &batch_api::Job) -> Option<CellSpec<'_>> {
    job.spec.as_ref().and_then(|spec| {
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

fn job_images(job: &batch_api::Job) -> Option<CellSpec<'_>> {
    job.spec.as_ref().and_then(|spec| {
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

fn job_selector(job: &batch_api::Job) -> Option<CellSpec<'_>> {
    job.spec.as_ref().and_then(|spec| {
        spec.selector.as_ref().and_then(|selector| {
            selector
                .match_labels
                .as_ref()
                .map(|match_labels| keyval_string(match_labels.iter(), None).into())
        })
    })
}

list_command!(
    Jobs,
    "jobs",
    "Get jobs (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("Show job labels (deprecated, use --show labels)")
                .takes_value(false)
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter jobs by the specified regex")
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
    vec!["job", "jobs"],
    noop_complete!(),
    [].into_iter(),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => batch_api::Job::list_namespaced_job(ns, Default::default())?,
            None => batch_api::Job::list_job_for_all_namespaces(Default::default())?,
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
            Some(&JOB_EXTRACTORS),
            job_to_kobj,
        )
    }
);
