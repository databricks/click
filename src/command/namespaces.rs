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
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, sort_arg, start_clap, Cmd},
    command::{run_list_command, Extractor},
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
    |clap: ClapCommand<'static>| clap.arg(
        Arg::new("namespace")
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
        Ok(())
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
    |clap: ClapCommand<'static>| {
        clap.arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(sort_arg(COL_FLAGS, None))
        .arg(
            Arg::new("reverse")
                .short('R')
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
        let (request, _response_body) = api::Namespace::list_namespace(Default::default())?;
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
        )
    }
);
