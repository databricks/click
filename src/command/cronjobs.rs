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
use k8s_openapi::api::batch::v1beta1 as batch_api;

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
    static ref JOB_EXTRACTORS: HashMap<String, Extractor<batch_api::CronJob>> = {
        let mut m: HashMap<String, Extractor<batch_api::CronJob>> = HashMap::new();
        m.insert("Schedule".to_owned(), cjob_schedule);
        m.insert("Suspend".to_owned(), cjob_suspend);
        m.insert("Active".to_owned(), cjob_active);
        m.insert("Last Schedule".to_owned(), cjob_last_schedule);
        m.insert("Containers".to_owned(), cjob_containers);
        m.insert("Images".to_owned(), cjob_images);
        m.insert("Selector".to_owned(), cjob_selector);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("schedule", "Schedule"),
    ("suspend", "Suspend"),
    ("active", "Active"),
    ("lastschedule", "Last Schedule"),
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

fn cjob_to_kobj(cjob: &batch_api::CronJob) -> KObj {
    let meta = &cjob.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::CronJob,
    }
}

fn cjob_schedule(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    cjob.spec.as_ref().map(|spec| spec.schedule.as_str().into())
}

fn cjob_suspend(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    cjob.spec
        .as_ref()
        .and_then(|spec| spec.suspend.map(|sus| format!("{sus}").into()))
}

fn cjob_active(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    let avec = cjob.status.as_ref().and_then(|stat| stat.active.as_ref());
    let cellspec = match avec {
        Some(vec) => format!("{}", vec.len()).into(),
        None => "0".into(),
    };
    Some(cellspec)
}

fn cjob_last_schedule(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    cjob.status.as_ref().and_then(|stat| {
        stat.last_schedule_time
            .as_ref()
            .map(|time| time_since(time.0).into())
    })
}

fn cjob_containers(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    let jobspec = cjob.spec.as_ref().map(|spec| &spec.job_template);
    jobspec.and_then(|jspec| {
        jspec.spec.as_ref().and_then(|spec| {
            spec.template.spec.as_ref().map(|pod_spec| {
                let names: Vec<&str> = pod_spec
                    .containers
                    .iter()
                    .map(|cont| cont.name.as_str())
                    .collect();
                names.join(", ").into()
            })
        })
    })
}

fn cjob_images(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    let jobspec = cjob.spec.as_ref().map(|spec| &spec.job_template);
    jobspec.and_then(|jspec| {
        jspec.spec.as_ref().and_then(|spec| {
            spec.template.spec.as_ref().map(|pod_spec| {
                let names: Vec<&str> = pod_spec
                    .containers
                    .iter()
                    .map(|cont| cont.image.as_deref().unwrap_or("<unknown>"))
                    .collect();
                names.join(", ").into()
            })
        })
    })
}

fn cjob_selector(cjob: &batch_api::CronJob) -> Option<CellSpec<'_>> {
    let jobspec = cjob.spec.as_ref().map(|spec| &spec.job_template);
    jobspec.and_then(|jspec| {
        jspec.spec.as_ref().and_then(|spec| {
            spec.selector.as_ref().and_then(|selector| {
                selector
                    .match_labels
                    .as_ref()
                    .map(|match_labels| keyval_string(match_labels.iter(), None).into())
            })
        })
    })
}

list_command!(
    CronJobs,
    "cronjobs",
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
    vec!["cronjob", "cronjobs"],
    noop_complete!(),
    [].into_iter(),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => batch_api::CronJob::list_namespaced_cron_job(ns, Default::default())?,
            None => batch_api::CronJob::list_cron_job_for_all_namespaces(Default::default())?,
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
            cjob_to_kobj,
        )
    }
);
