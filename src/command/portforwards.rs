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
use comfy_table::{Cell, Table, CellAlignment};
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    completer,
    env::{self, Env},
    error::ClickError,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, stderr, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

command!(
    PortForward,
    "port-forward",
    "Forward one (or more) local ports to the currently active pod",
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("ports")
                .help("the ports to forward")
                .multiple_values(true)
                .validator(|s: &str| {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() > 2 {
                        Err(format!(
                            "Invalid port specification '{}', can only contain one ':'",
                            s
                        ))
                    } else {
                        for part in parts {
                            if !part.is_empty() {
                                if let Err(e) = part.parse::<u32>() {
                                    return Err(e.to_string());
                                }
                            }
                        }
                        Ok(())
                    }
                })
                .required(true)
                .index(1)
        )
        .after_help(
            "
Examples:
  # Forward local ports 5000 and 6000 to pod ports 5000 and 6000
  port-forward 5000 6000

  # Forward port 8080 locally to port 9090 on the pod
  port-forward 8080:9090

  # Forwards a random port locally to port 3456 on the pod
  port-forward 0:3456

  # Forwards a random port locally to port 3456 on the pod
  port-forward :3456"
        ),
    vec!["pf", "port-forward"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let ports: Vec<_> = matches.values_of("ports").unwrap().collect(); // unwrap safe, required

        let (pod, ns) = {
            let epod = env.current_pod();
            match epod {
                Some(p) => (
                    p.name().to_string(),
                    p.namespace.as_ref().unwrap().to_string(),
                ),
                None => {
                    write!(stderr(), "No active pod").unwrap_or(());
                    return Ok(()); // TODO: Return error
                }
            }
        };

        let context = if let Some(ref context) = env.context {
            context.name.clone()
        } else {
            return Err(ClickError::CommandError("No active context".to_string()));
        };

        match Command::new("kubectl")
            .arg("--namespace")
            .arg(ns)
            .arg("--context")
            .arg(context)
            .arg("port-forward")
            .arg(&pod)
            .args(ports.iter())
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                let mut stdout = child.stdout.take().unwrap();
                let output = Arc::new(Mutex::new(String::new()));
                let output_clone = output.clone();

                thread::spawn(move || {
                    let mut buffer = [0; 128];
                    loop {
                        match stdout.read(&mut buffer[..]) {
                            Ok(read) => {
                                if read > 0 {
                                    let readstr = String::from_utf8_lossy(&buffer[0..read]);
                                    let mut res = output_clone.lock().unwrap();
                                    res.push_str(&*readstr);
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                write!(stderr(), "Error reading child output: {}", e).unwrap_or(());
                                break;
                            }
                        }
                    }
                });

                let pvec: Vec<String> = ports.iter().map(|s| (*s).to_owned()).collect();
                clickwriteln!(writer, "Forwarding port(s): {}", pvec.join(", "));

                env.add_port_forward(env::PortForward {
                    child,
                    pod,
                    ports: pvec,
                    output,
                });
            }
            Err(e) => match e.kind() {
                io::ErrorKind::NotFound => {
                    writeln!(
                        stderr(),
                        "Could not find kubectl binary. Is it in your PATH?"
                    )
                    .unwrap_or(());
                }
                _ => {
                    write!(
                        stderr(),
                        "Couldn't execute kubectl, not forwarding.  Error is: {}",
                        e
                    )
                    .unwrap_or(());
                }
            },
        }
        Ok(()) // TODO: Return errors above if things fail
    }
);

/// Print out port forwards found in iterator
fn print_pfs(pfs: std::slice::IterMut<env::PortForward>, writer: &mut ClickWriter) {
    let mut table = Table::new();
    table.load_preset(crate::table::UTF8_TABLE_STYLE);
    let mut empty = true;
    table.set_header(vec!["####", "Pod", "Ports", "Status"]);
    for (i, pf) in pfs.enumerate() {
        let mut row = Vec::new();
        row.push(Cell::new(format!("{}", i).as_str()).set_alignment(CellAlignment::Right));
        row.push(Cell::new(pf.pod.as_str()));
        row.push(Cell::new(pf.ports.join(", ").as_str()));

        let status = match pf.child.try_wait() {
            Ok(Some(stat)) => format!("Exited with code {}", stat),
            Ok(None) => "Running".to_string(),
            Err(e) => format!("Error: {}", e),
        };
        row.push(Cell::new(status.as_str()));

        table.add_row(row);
        empty = false;
    }
    if empty {
        clickwriteln!(
            writer,
            "No active port forwards, see `port-forward -h` for help creating one"
        );
    } else {
        println!("{table}");
    }
}

command!(
    PortForwards,
    "port-forwards",
    "List or control active port forwards.  Default is to list.",
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("action")
                .help("Action to take")
                .required(false)
                .possible_values(&["list", "output", "stop"])
                .index(1)
        )
        .arg(
            Arg::new("index")
                .help("Index (from 'port-forwards list') of port forward to take action on")
                .validator(|s: &str| s.parse::<usize>().map(|_| ()).map_err(|e| e.to_string()))
                .required(false)
                .index(2)
        )
        .after_help(
            "Example:
  # List all active port forwards
  pfs

  # Stop item number 3 in list from above command
  pfs stop 3"
        ),
    vec!["pfs", "port-forwards"],
    vec![&completer::portforwardaction_values_completer],
    no_named_complete!(),
    |matches, env, writer| {
        let stop = matches.is_present("action") && matches.value_of("action").unwrap() == "stop";
        let output =
            matches.is_present("action") && matches.value_of("action").unwrap() == "output";
        if let Some(index) = matches.value_of("index") {
            let i = index.parse::<usize>().unwrap();
            match env.get_port_forward(i) {
                Some(pf) => {
                    if stop {
                        clickwrite!(writer, "Stop port-forward: ");
                    }
                    clickwrite!(writer, "Pod: {}, Port(s): {}", pf.pod, pf.ports.join(", "));

                    if output {
                        clickwriteln!(writer, " Output:{}", *pf.output.lock().unwrap());
                    }
                }
                None => {
                    clickwriteln!(writer, "Invalid index (try without args to get a list)");
                    return Ok(()); // TODO: Return error
                }
            }

            if stop {
                clickwrite!(writer, "  [y/N]? ");
                io::stdout().flush().expect("Could not flush stdout");
                let mut conf = String::new();
                if io::stdin().read_line(&mut conf).is_ok() {
                    if conf.trim() == "y" || conf.trim() == "yes" {
                        match env.stop_port_forward(i) {
                            Ok(()) => {
                                clickwriteln!(writer, "Stopped");
                            }
                            Err(e) => {
                                write!(stderr(), "Failed to stop: {}", e).unwrap_or(());
                            }
                        }
                    } else {
                        clickwriteln!(writer, "Not stopping");
                    }
                } else {
                    clickwriteln!(writer, "Could not read response, not stopping.");
                }
            } else {
                clickwrite!(writer, "\n"); // just flush the above description
            }
        } else {
            print_pfs(env.get_port_forwards(), writer);
        }
        Ok(())
    }
);
