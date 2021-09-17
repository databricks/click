use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::core::v1 as api;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{run_list_command, sort_arg, Extractor},
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
    static ref NS_EXTRACTORS: HashMap<String, Extractor<api::Namespace>> = {
        let mut m: HashMap<String, Extractor<api::Namespace>> = HashMap::new();
        m.insert("Status".to_owned(), namespace_status);
        m
    };
}

const COL_MAP: &[(&str, &str)] = &[("name", "Name"), ("age", "Age"), ("status", "Status")];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

command!(
    Namespace,
    "namespace",
    "Set the current namespace (no argument to clear namespace)",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("namespace")
            .help("The namespace to use")
            .required(false)
            .index(1)
    ),
    vec!["ns", "namespace"],
    vec![&completer::namespace_completer],
    no_named_complete!(),
    |matches, env, _| {
        let ns = matches.value_of("namespace");
        env.set_namespace(ns);
    }
);

fn namespace_to_kobj(namespace: &api::Namespace) -> KObj {
    KObj {
        name: namespace
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<Unknown>".into()),
        namespace: None,
        typ: ObjType::Namespace,
    }
}

fn namespace_status(namespace: &api::Namespace) -> Option<CellSpec<'_>> {
    namespace
        .status
        .as_ref()
        .and_then(|stat| stat.phase.as_ref().map(|p| p.as_str().into()))
}

command!(
    Namespaces,
    "namespaces",
    "Get namespaces in current context",
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(sort_arg(COL_FLAGS, None))
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        )
    },
    vec!["namespaces"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let cols: Vec<&str> = COL_MAP.iter().map(|(_, col)| *col).collect();
        let (request, _response_body) = api::Namespace::list_namespace(Default::default()).unwrap();
        run_list_command(
            matches,
            env,
            writer,
            cols,
            request,
            COL_MAP,
            None,
            Some(&NS_EXTRACTORS),
            namespace_to_kobj,
        );
    }
);
