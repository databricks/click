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
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    completer,
    env::Env,
    error::ClickError,
    kobj::KObj,
    output::ClickWriter,
};

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Write};
use std::process::Command;

#[allow(clippy::too_many_arguments)]
fn do_copy(
    pod: &KObj,
    context: &str,
    src: &str,
    dest: &str,
    from: bool,
    retries: &str,
    writer: &mut ClickWriter,
) -> Result<(), ClickError> {
    let ns = pod.namespace.as_ref().unwrap();
    let src_arg: Cow<str> = if from {
        format!("{}/{}:{}", ns, pod.name(), src).into()
    } else {
        src.into()
    };

    let dest_arg: Cow<str> = if from {
        dest.into()
    } else {
        format!("{}/{}:{}", ns, pod.name(), dest).into()
    };

    let mut command = Command::new("kubectl");
    command
        .arg("cp")
        .arg("--context")
        .arg(context)
        .arg(&*src_arg)
        .arg(&*dest_arg)
        .arg("--retries")
        .arg(retries);
    match command.output() {
        Ok(output) => {
            if output.status.success() {
                clickwriteln!(writer, "copied");
                Ok(())
            } else {
                Err(ClickError::CommandError(format!(
                    "\nFailed to copy:{}{}",
                    std::str::from_utf8(&output.stdout).unwrap(),
                    std::str::from_utf8(&output.stderr).unwrap()
                )))
            }
        }
        Err(e) => {
            if let io::ErrorKind::NotFound = e.kind() {
                Err(ClickError::CommandError(
                    "Could not find kubectl binary. Is it in your PATH?".to_string(),
                ))
            } else {
                Err(ClickError::Io(e))
            }
        }
    }
}

/// a clap validator for i32
pub fn valid_i32(s: &str) -> Result<(), String> {
    s.parse::<i32>().map(|_| ()).map_err(|e| e.to_string())
}

command!(
    Copy,
    "copy",
    "copy files to/from the specified pod(s)",
    |clap: ClapCommand<'static>| {
        clap
        .arg(
            Arg::new("src")
                .help("the source file")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::new("dest")
                .help("the destination file")
                .required(true)
                .index(2)
        )
        .arg(
            Arg::new("direction")
                .short('d')
                .long("direction")
                .help("Should the src file be copied to or from the pod.")
                .takes_value(true)
                .possible_values(&["to", "from"])
                .default_value("from")
        )
        .arg(
            Arg::new("container")
                .short('c')
                .long("container")
                .help("Copy from/to the specified container")
                .takes_value(true)
        )
        .arg(
            Arg::new("nopreserve")
                .long("no-preserve")
                .help("When copying, don't try and preserve file ownership and permissions")
                .takes_value(false)
        )
        .arg(
            Arg::new("retries")
                .long("retries")
                .help("How many times to retry the copy. Specify 0 for no retry, or a negative value for infinte retries")
                .validator(valid_i32)
                .takes_value(true)
                .default_value("0")
        )
        .after_help(
            "
Examples:
  # Copy /tmp/bar from the selected pod to /tmp/foo locally:
  cp /tmp/bar /tmp/foo

  # Copy /tmp/foo in the selected pod in a specific container to /tmp/bar locally:
  cp /tmp/foo /tmp/bar -c <container>

  # Copy the local directory /tmp/foof to /tmp/barf in the selected pod:
  copy --direction to /tmp/foof /tmp/barf"
        )
    },
    vec!["cp", "copy"],
    noop_complete!(),
    [(
        "container".to_string(),
        completer::container_completer as fn(&str, &Env) -> Vec<RustlinePair>
    )]
    .into_iter()
    .collect(),
    |matches, env, writer| {
        let context = env.context.as_ref().ok_or_else(|| {
            ClickError::CommandError("Need an active context in order to copy.".to_string())
        })?;
        let src = matches.value_of("src").unwrap(); // safe, required
        let dest = matches.value_of("dest").unwrap(); // safe, required
        let from = matches.value_of("direction").unwrap() == "from"; // safe, has default
        let retries = matches.value_of("retries").unwrap(); // safe, has default
        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| {
                if obj.is_pod() {
                    do_copy(obj, &context.name, src, dest, from, retries, writer)
                } else {
                    Err(ClickError::CommandError(
                        "Copy only possible on pods".to_string(),
                    ))
                }
            },
        )
    }
);
