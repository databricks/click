use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::storage::v1 as api_storage;

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
    static ref SC_EXTRACTORS: HashMap<String, Extractor<api_storage::StorageClass>> = {
        let mut m: HashMap<String, Extractor<api_storage::StorageClass>> = HashMap::new();
        m.insert("Provisioner".to_owned(), sc_provisioner);
        m
    };
}

const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("provisioner", "Provisioner"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[("labels", "Labels")];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn storageclass_to_kobj(node: &api_storage::StorageClass) -> KObj {
    KObj {
        name: node
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<Unknown>".into()),
        namespace: None,
        typ: ObjType::StorageClass,
    }
}

fn sc_provisioner(sc: &api_storage::StorageClass) -> Option<CellSpec<'_>> {
    Some(sc.provisioner.as_str().into())
}

list_command!(
    StorageClasses,
    "storageclasses",
    "Get storage classes in the current context",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("labels")
                .short("L")
                .long("labels")
                .help("include labels in output (deprecated, use --show labels")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        )
    },
    vec!["storageclass", "storageclasses"],
    noop_complete!(),
    IntoIter::new([]),
    |matches, env, writer| {
        let cols: Vec<&str> = COL_MAP.iter().map(|(_, col)| *col).collect();
        let (request, _response_body) =
            api_storage::StorageClass::list_storage_class(Default::default())?;

        run_list_command(
            matches,
            env,
            writer,
            cols,
            request,
            COL_MAP,
            Some(EXTRA_COL_MAP),
            Some(&SC_EXTRACTORS),
            storageclass_to_kobj,
        )
    }
);
