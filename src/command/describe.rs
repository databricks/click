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
use clap::{App, Arg};
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    completer,
    env::Env,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

command!(
    Describe,
    "describe",
    "Describe the active kubernetes object.",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the full description in json")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("yaml")
                .short("y")
                .long("yaml")
                .help("Print the full description in yaml")
                .takes_value(false)
        ),
    vec!["describe"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| obj.describe(&matches, env, writer),
        )
    }
);
