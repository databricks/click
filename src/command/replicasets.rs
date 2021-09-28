use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::apps::v1 as apps_api;

use crate::{
    command::command_def::{exec_match, show_arg, sort_arg, start_clap, Cmd},
    command::{keyval_string, run_list_command, Extractor},
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
    static ref RS_EXTRACTORS: HashMap<String, Extractor<apps_api::ReplicaSet>> = {
        let mut m: HashMap<String, Extractor<apps_api::ReplicaSet>> = HashMap::new();
        m.insert("Current".to_owned(), rs_current);
        m.insert("Containers".to_owned(), rs_containers);
        m.insert("Desired".to_owned(), rs_desired);
        m.insert("Images".to_owned(), rs_images);
        m.insert("Ready".to_owned(), rs_ready);
        m.insert("Selector".to_owned(), rs_selector);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("desired", "Desired"),
    ("current", "Current"),
    ("ready", "Ready"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[
    ("namespace", "Namespace"),
    ("containers", "Containers"),
    ("images", "Images"),
    ("selector", "Selector"),
    ("labels", "Labels"),
];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn rs_to_kobj(replicaset: &apps_api::ReplicaSet) -> KObj {
    let meta = &replicaset.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::ReplicaSet,
    }
}

fn rs_containers(replicaset: &apps_api::ReplicaSet) -> Option<CellSpec<'_>> {
    replicaset.spec.as_ref().and_then(|spec| {
        spec.template.as_ref().and_then(|template| {
            template.spec.as_ref().map(|pod_spec| {
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

fn rs_images(replicaset: &apps_api::ReplicaSet) -> Option<CellSpec<'_>> {
    replicaset.spec.as_ref().and_then(|spec| {
        spec.template.as_ref().and_then(|template| {
            template.spec.as_ref().map(|pod_spec| {
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

fn rs_current(replicaset: &apps_api::ReplicaSet) -> Option<CellSpec<'_>> {
    replicaset
        .status
        .as_ref()
        .map(|stat| format!("{}", stat.replicas).into())
}

fn rs_desired(replicaset: &apps_api::ReplicaSet) -> Option<CellSpec<'_>> {
    replicaset.spec.as_ref().map(|spec| match spec.replicas {
        Some(desired) => format!("{}", desired).into(),
        None => "Unspecified".into(),
    })
}

fn rs_ready(replicaset: &apps_api::ReplicaSet) -> Option<CellSpec<'_>> {
    replicaset
        .status
        .as_ref()
        .map(|stat| match stat.ready_replicas {
            Some(ready) => format!("{}", ready).into(),
            None => "0".into(),
        })
}

fn rs_selector(replicaset: &apps_api::ReplicaSet) -> Option<CellSpec<'_>> {
    replicaset
        .spec
        .as_ref()
        .map(|spec| keyval_string(&spec.selector.match_labels).into())
}

list_command!(
    ReplicaSets,
    "replicasets",
    "Get replicasets (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("show_label")
                .short("L")
                .long("labels")
                .help("Show replicasets labels (deprecated, use --show labels)")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter replicasets by the specified regex")
                .takes_value(true)
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        ),
    vec!["rs", "replicasets"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => apps_api::ReplicaSet::list_namespaced_replica_set(ns, Default::default())?,
            None => apps_api::ReplicaSet::list_replica_set_for_all_namespaces(Default::default())?,
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
            Some(&RS_EXTRACTORS),
            rs_to_kobj,
        )
    }
);
