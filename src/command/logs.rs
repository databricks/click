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

use chrono::offset::{Local, Utc};
use chrono::DateTime;
use clap::{Arg, Command as ClapCommand};
use k8s_openapi::api::core::v1 as api;

use reqwest::blocking::Response;
use rustyline::completion::Pair as RustlinePair;
use strfmt::strfmt;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    command::{parse_duration, valid_date, valid_duration, valid_u32},
    completer,
    env::Env,
    error::ClickError,
    kobj::{KObj, ObjType},
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::thread;
use std::time::Duration;

// logs helper commands
fn pick_container<'a>(obj: &'a KObj, writer: &mut ClickWriter) -> &'a str {
    match obj.typ {
        ObjType::Pod { ref containers, .. } => {
            if containers.len() > 1 {
                clickwriteln!(writer, "Pod has multiple containers, picking the first one");
            }
            containers[0].as_str()
        }
        _ => unreachable!(),
    }
}

#[allow(clippy::ptr_arg)]
fn write_logs_to_file(
    env: &Env,
    path: &PathBuf,
    mut reader: BufReader<Response>,
) -> Result<(), ClickError> {
    let mut file = std::fs::File::create(path)?;
    let mut buffer = [0; 1024];
    while !env.ctrlcbool.load(Ordering::SeqCst) {
        let amt = reader.read(&mut buffer[..])?;
        if amt == 0 {
            break;
        }
        file.write_all(&buffer[0..amt])?;
    }
    file.flush().map_err(ClickError::from)
}

#[allow(clippy::too_many_arguments)]
fn do_logs<'a>(
    obj: &'a KObj,
    env: &Env,
    mut opts: api::ReadNamespacedPodLogOptional<'a>,
    cont_opt: Option<&'a str>,
    output_opt: Option<&str>,
    editor: bool,
    editor_opt: Option<&str>,
    timeout: Option<Duration>,
    writer: &mut ClickWriter,
) -> Result<(), ClickError> {
    let cont = cont_opt.unwrap_or_else(|| pick_container(obj, writer));
    opts.container = Some(cont);

    let (request, _resp) =
        api::Pod::read_namespaced_pod_log(obj.name(), obj.namespace.as_ref().unwrap(), opts)?;

    let logs_reader_res = env.run_on_context(|c| c.execute_reader(env.get_impersonate_user(), request, timeout));
    match logs_reader_res {
        Ok(lreader) => {
            let mut reader = BufReader::new(lreader);
            env.ctrlcbool.store(false, Ordering::SeqCst);
            if let Some(output) = output_opt {
                let mut fmtvars = HashMap::new();
                fmtvars.insert("name".to_string(), obj.name());
                fmtvars.insert(
                    "namespace".to_string(),
                    obj.namespace.as_deref().unwrap_or("[none]"),
                );
                let ltime = Local::now().to_rfc3339();
                fmtvars.insert("time".to_string(), &ltime);
                match strfmt(output, &fmtvars) {
                    Ok(file_path) => {
                        let pbuf = file_path.into();
                        write_logs_to_file(env, &pbuf, reader)?;
                        println!("Wrote logs to {}", pbuf.to_str().unwrap());
                        Ok(())
                    }
                    Err(e) => Err(ClickError::CommandError(format!(
                        "Can't generate output path: {e}"
                    ))),
                }
            } else if editor {
                // We're opening in an editor, save to a temp
                let editor = if let Some(v) = editor_opt {
                    v.to_owned()
                } else if let Some(ref e) = env.click_config.editor {
                    e.clone()
                } else {
                    match std::env::var("EDITOR") {
                        Ok(ed) => ed,
                        Err(e) => {
                            return Err(ClickError::CommandError(format!(
                                "Could not get EDITOR environment variable: {e}"
                            )));
                        }
                    }
                };
                let tmpdir = match env.tempdir {
                    Ok(ref td) => td,
                    Err(ref e) => {
                        return Err(ClickError::CommandError(format!(
                            "Failed to create tempdir: {e}"
                        )));
                    }
                };
                let file_path = tmpdir.path().join(format!(
                    "{}_{}_{}.log",
                    obj.name(),
                    cont,
                    Local::now().to_rfc3339()
                ));
                write_logs_to_file(env, &file_path, reader)?;

                clickwriteln!(writer, "Logs downloaded, starting editor");
                let expr = if editor.contains(' ') {
                    // split the whitespace
                    let mut eargs: Vec<&str> = editor.split_whitespace().collect();
                    eargs.push(file_path.to_str().unwrap());
                    duct::cmd(eargs[0], &eargs[1..])
                } else {
                    cmd!(editor, file_path)
                };
                expr.start()?;
                Ok(())
            } else {
                let (sender, receiver) = channel();
                thread::spawn(move || {
                    loop {
                        let mut line = String::new();
                        if let Ok(amt) = reader.read_line(&mut line) {
                            if amt > 0 {
                                if sender.send(line).is_err() {
                                    // probably user hit ctrl-c, just stop
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                });
                while !env.ctrlcbool.load(Ordering::SeqCst) {
                    match receiver.recv_timeout(Duration::new(1, 0)) {
                        Ok(line) => {
                            clickwrite!(writer, "{}", line); // newlines already in line
                        }
                        Err(e) => {
                            if let RecvTimeoutError::Disconnected = e {
                                break;
                            }
                        }
                    }
                }
                Ok(())
            }
        }
        Err(e) => Err(e),
    }
}

command!(
    Logs,
    "logs",
    "Get logs from a container in the current pod",
    |clap: ClapCommand<'static>| {
        let ret = clap
            .arg(
                Arg::new("container")
                    .help("Specify which container to get logs from")
                    .required(false)
                    .index(1),
            )
            .arg(
                Arg::new("follow")
                    .short('f')
                    .long("follow")
                    .help("Follow the logs as new records arrive (stop with ^C)")
                    .conflicts_with("editor")
                    .conflicts_with("output")
                    .takes_value(false),
            )
            .arg(
                Arg::new("tail")
                    .short('t')
                    .long("tail")
                    .validator(valid_u32)
                    .help("Number of lines from the end of the logs to show")
                    .takes_value(true),
            )
            .arg(
                Arg::new("previous")
                    .short('p')
                    .long("previous")
                    .help("Return previous terminated container logs")
                    .takes_value(false),
            )
            .arg(
                Arg::new("since")
                    .long("since")
                    .conflicts_with("sinceTime")
                    .validator(valid_duration)
                    .help(
                        "Only return logs newer than specified relative duration,
 e.g. 5s, 2m, 3m5s, 1h2min5sec",
                    )
                    .takes_value(true),
            )
            .arg(
                Arg::new("sinceTime")
                    .long("since-time")
                    .conflicts_with("since")
                    .validator(valid_date)
                    .help(
                        "Only return logs newer than specified RFC3339 date. Eg:
 1996-12-19T16:39:57-08:00",
                    )
                    .takes_value(true),
            )
            .arg(
                Arg::new("timestamps")
                    .long("timestamps")
                    .help(
                        "Include an RFC3339 or RFC3339Nano timestamp at the beginning \
                         of every line of log output.",
                    )
                    .takes_value(false),
            )
            .arg(
                Arg::new("editor")
                    .long("editor")
                    .short('e')
                    .conflicts_with("follow")
                    .conflicts_with("output")
                    .help(
                        "Open fetched logs in an editor rather than printing them out. with \
                         --editor ARG, ARG is used as the editor command, otherwise click \
                         environment editor (see set/env commands) is used, otherwise the \
                         $EDITOR environment variable is used.",
                    )
                    .takes_value(true)
                    .min_values(0),
            )
            .arg(
                Arg::new("output")
                    .long("output")
                    .short('o')
                    .conflicts_with("editor")
                    .conflicts_with("follow")
                    .help(
                        "Write output to a file at the specified path instead of printing it. \
                         This path can be templated with {name}, {namespace}, and {time} to write \
                         individual files for each pod in a range. (See 'help ranges').",
                    )
                    .takes_value(true),
            );
        k8s_if_ge_1_17! {
            let ret = ret.arg(
                Arg::new("insecure")
                    .long("insecure-skip-tls-verify-backend")
                    .help("Skip verifying the identity of the kubelet that logs are requested from. \
                           This could allow an attacker to provide invalid logs. \
                           Useful if your kubelet serving certs have expired or similar.")
                    .takes_value(false)
            );
        }
        ret
    },
    vec!["logs"],
    vec![&completer::container_completer],
    no_named_complete!(),
    #[allow(clippy::cognitive_complexity)]
    |matches, env, writer| {
        let mut opts: api::ReadNamespacedPodLogOptional = Default::default();

        if matches.is_present("follow") {
            opts.follow = Some(true);
        }
        k8s_if_ge_1_17! {
            if matches.is_present("insecure") {
                opts.insecure_skip_tls_verify_backend = Some(true);
            }
        }
        if matches.is_present("previous") {
            opts.previous = Some(true);
        }
        if matches.is_present("tail") {
            let lines = matches.value_of("tail").unwrap().parse::<i64>().unwrap();
            opts.tail_lines = Some(lines);
        }
        if matches.is_present("since") {
            // all unwraps already validated
            let dur = parse_duration(matches.value_of("since").unwrap()).unwrap();
            let dur = match i64::try_from(dur.as_secs()) {
                Ok(d) => d,
                Err(e) => {
                    clickwriteln!(writer, "Invalid duration in --since: {}", e);
                    return Ok(()); // TODO: Return error
                }
            };
            opts.since_seconds = Some(dur);
        }
        if matches.is_present("sinceTime") {
            let specified =
                DateTime::parse_from_rfc3339(matches.value_of("sinceTime").unwrap()).unwrap();
            let dur = Utc::now().signed_duration_since(specified.with_timezone(&Utc));
            opts.since_seconds = Some(dur.num_seconds());
        }
        let timeout = if matches.is_present("follow") {
            None
        } else {
            Some(Duration::new(20, 0)) // TODO what's a reasonable timeout here?
        };
        if matches.is_present("timestamps") {
            opts.timestamps = Some(true);
        }

        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| {
                if obj.is_pod() {
                    do_logs(
                        obj,
                        env,
                        opts,
                        matches.value_of("container"),
                        matches.value_of("output"),
                        matches.is_present("editor"),
                        matches.value_of("editor"),
                        timeout,
                        writer,
                    )
                } else {
                    Err(ClickError::CommandError(
                        "Logs only available on a pod".to_string(),
                    ))
                }
            },
        )
    }
);
