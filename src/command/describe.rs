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
use clap::{Command as ClapCommand, Arg};
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

use super::events::print_events_for_obj;

command!(
    Describe,
    "describe",
    "Describe the active kubernetes object.",
    |clap: ClapCommand<'static>| {
        clap.arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Print the full description in json")
                .takes_value(false),
        )
        .arg(
            Arg::new("yaml")
                .short('y')
                .long("yaml")
                .help("Print the full description in yaml")
                .takes_value(false),
        )
        .arg(
            Arg::new("include_events")
                .short('e')
                .long("events")
                .help(
                    "If true, include events in the output, if false, do not. \
                     Default can be set by 'set describe_include_events [true/false]'",
                )
                .takes_value(true)
                .possible_values(&["true", "false"]),
        )
    },
    vec!["describe"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let mut include_events = env.click_config.describe_include_events;
        if let Some(b) = matches.value_of("include_events") {
            include_events = b.parse().unwrap(); // safe, validated to be true/false
        }
        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| {
                obj.describe(&matches, env, writer)?;
                if include_events {
                    clickwriteln!(writer, "Events:");
                    print_events_for_obj(obj, env, writer)
                } else {
                    Ok(())
                }
            },
        )
    }
);
