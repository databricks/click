use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::apps::v1 as apps_api;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{run_list_command, show_arg, sort_arg, Extractor},
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
            Some(current) => format!("{}", current).into(),
            None => "0".into(),
        })
}

fn ss_desired(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset
        .status
        .as_ref()
        .map(|stat| format!("{}", stat.replicas).into())
}

fn ss_ready(statefulset: &apps_api::StatefulSet) -> Option<CellSpec<'_>> {
    statefulset
        .status
        .as_ref()
        .map(|stat| match stat.ready_replicas {
            Some(ready) => format!("{}", ready).into(),
            None => "0".into(),
        })
}

list_command!(
    StatefulSets,
    "statefulsets",
    "Get statefulsets (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("show_label")
                .short("L")
                .long("labels")
                .help("Show statefulsets labels (deprecated, use --show labels)")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter statefulsets by the specified regex")
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
    vec!["ss", "statefulsets"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => {
                apps_api::StatefulSet::list_namespaced_stateful_set(ns, Default::default()).unwrap()
            }
            None => apps_api::StatefulSet::list_stateful_set_for_all_namespaces(Default::default())
                .unwrap(),
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
        );
    }
);
