use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::apps::v1 as apps_api;
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

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{stderr, Write};

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
    static ref EXTRA_COLS: Vec<(&'static str, &'static str)> =
        vec![("containers", "Containers"), ("images", "Images")];
}

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

command!(
    StatefulSets,
    "statefulsets",
    "Get statefulsets (in current namespace if set)",
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
        .arg(show_arg(
            &EXTRA_COLS
                .iter()
                .map(|(flag, _)| *flag)
                .collect::<Vec<&str>>(),
            true,
        ))
        .arg(sort_arg(
            &["name", "current", "desired", "ready", "age"],
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
        ),
    vec!["ss", "statefulsets"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let regex = match crate::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let (request, _response_body) = match &env.namespace {
            Some(ns) => {
                apps_api::StatefulSet::list_namespaced_stateful_set(ns, Default::default()).unwrap()
            }
            None => apps_api::StatefulSet::list_stateful_set_for_all_namespaces(Default::default())
                .unwrap(),
        };
        let ss_list_opt: Option<List<apps_api::StatefulSet>> =
            env.run_on_context(|c| c.execute_list(request));

        let mut cols = vec!["Name", "Desired", "Current", "Ready", "Age"];

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
                "current" => SortFunc::Post("current"),
                "desired" => SortFunc::Post("desired"),
                "ready" => SortFunc::Post("Ready"),
                "name" => SortFunc::Post("Name"),
                "labels" => {
                    flags.push("labels");
                    SortFunc::Post("Labels")
                }
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
            ss_list_opt,
            Some(&SS_EXTRACTORS),
            regex,
            sort,
            matches.is_present("reverse"),
            ss_to_kobj,
        );
    }
);
