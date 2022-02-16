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
    |clap: ClapCommand<'static>| {
        clap.arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("include labels in output (deprecated, use --show labels")
                .takes_value(false),
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::new("reverse")
                .short('R')
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
