// Copyright 2017 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The Command Line Interactive Contoller for Kubernetes

#[macro_use]
extern crate duct;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate prettytable;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
mod output;

extern crate ansi_term;
extern crate base64;
extern crate chrono;
#[macro_use]
extern crate clap;
extern crate ctrlc;
extern crate der_parser;
extern crate duct_sh;
extern crate humantime;
extern crate hyper;
extern crate hyper_sync_rustls;
extern crate os_pipe;
extern crate regex;
extern crate ring;
extern crate rustls;
extern crate rustyline;
extern crate serde;
extern crate serde_yaml;
extern crate tempdir;
extern crate term;
extern crate untrusted;
extern crate webpki;
extern crate dirs;

mod certs;
mod cmd;
mod completer;
mod connector;
mod config;
mod describe;
mod error;
mod kube;
mod parser;
mod subjaltnames;
mod table;
mod values;

use ansi_term::Colour::{Black, Blue, Cyan, Green, Purple, Red, Yellow};
use clap::{App, Arg};
use parser::Parser;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use tempdir::TempDir;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::process::Child;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cmd::Cmd;
use completer::ClickCompleter;
use config::{ClickConfig, Config};
use error::KubeError;
use kube::{ConfigMapList, DeploymentList, Kluster, NodeList, PodList, ReplicaSetList, SecretList,
           ServiceList, JobList};
use output::ClickWriter;
use values::val_str_opt;
use std::env;

/// An object we can have as a "current" thing
enum KObj {
    None,
    Pod {
        name: String,
        containers: Vec<String>,
    },
    Node(String),
    Deployment(String),
    Service(String),
    ReplicaSet(String),
    ConfigMap(String),
    Secret(String),
    Job(String),
}

enum LastList {
    None,
    PodList(PodList),
    NodeList(NodeList),
    DeploymentList(DeploymentList),
    ServiceList(ServiceList),
    ReplicaSetList(ReplicaSetList),
    ConfigMapList(ConfigMapList),
    SecretList(SecretList),
    JobList(JobList),
}

/// An ongoing port forward
struct PortForward {
    child: Child,
    pod: String,
    ports: Vec<String>,
    output: Arc<Mutex<String>>,
}

/// Keep track of our repl environment
pub struct Env {
    config: Config,
    click_config: ClickConfig,
    quit: bool,
    kluster: Option<Kluster>,
    namespace: Option<String>,
    current_object: KObj,
    pub current_object_namespace: Option<String>,
    last_objs: LastList,
    pub ctrlcbool: Arc<AtomicBool>,
    port_forwards: Vec<PortForward>,
    prompt: String,
    tempdir: std::io::Result<TempDir>,
}

impl Env {
    fn new(config: Config, click_config: ClickConfig) -> Env {
        let cbool = Arc::new(AtomicBool::new(false));
        let r = cbool.clone();
        ctrlc::set_handler(move || {
            r.store(true, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
        let namespace = click_config.namespace.clone();
        let context = click_config.context.clone();
        let mut env = Env {
            config: config,
            click_config: click_config,
            quit: false,
            kluster: None,
            namespace: namespace,
            current_object: KObj::None,
            current_object_namespace: None,
            last_objs: LastList::None,
            ctrlcbool: cbool,
            port_forwards: Vec::new(),
            prompt: format!(
                "[{}] [{}] [{}] > ",
                Red.paint("none"),
                Green.paint("none"),
                Yellow.paint("none")
            ),
            tempdir: TempDir::new("click"),
        };
        env.set_context(context.as_ref().map(|x| &**x));
        env
    }

    fn save_click_config(&mut self, click_path: PathBuf) {
        self.click_config.namespace = self.namespace.clone();
        self.click_config.context = self.kluster.as_ref().map(|k| k.name.clone());
        self.click_config
            .save_to_file(click_path.as_path().to_str().unwrap())
            .unwrap();
    }

    // sets the prompt string based on current settings
    fn set_prompt(&mut self) {
        self.prompt = format!(
            "[{}] [{}] [{}] > ",
            if let Some(ref k) = self.kluster {
                Red.bold().paint(k.name.as_str())
            } else {
                Red.paint("none")
            },
            if let Some(ref n) = self.namespace {
                Green.bold().paint(n.as_str())
            } else {
                Green.paint("none")
            },
            match self.current_object {
                KObj::None => Yellow.paint("none"),
                KObj::Pod { ref name, .. } => Yellow.bold().paint(name.as_str()),
                KObj::Node(ref name) => Blue.bold().paint(name.as_str()),
                KObj::Deployment(ref name) => Purple.bold().paint(name.as_str()),
                KObj::Service(ref name) => Cyan.bold().paint(name.as_str()),
                KObj::ReplicaSet(ref name) => Green.bold().paint(name.as_str()),
                KObj::ConfigMap(ref name) => Black.bold().paint(name.as_str()),
                KObj::Secret(ref name) => Red.bold().paint(name.as_str()),
                KObj::Job(ref name) => Purple.bold().paint(name.as_str()),
            }
        );
    }

    fn get_contexts(&self) -> &HashMap<String, ::config::ContextConf> {
        &self.config.contexts
    }

    fn set_context(&mut self, ctx: Option<&str>) {
        match ctx {
            Some(cname) => {
                self.kluster = match self.config.cluster_for_context(cname) {
                    Ok(k) => Some(k),
                    Err(e) => {
                        println!(
                            "[Warning] Couldn't find/load context {}, now no current context.  Error: {}",
                            cname,
                            e
                        );
                        None
                    }
                };
                self.set_prompt();
            }
            None => {} // no-op
        }
    }

    fn set_namespace(&mut self, namespace: Option<&str>) {
        let mut do_clear = false;
        if let (&Some(ref my_ns), Some(new_ns)) = (&self.namespace, namespace) {
            if my_ns.as_str() != new_ns {
                do_clear = true; // need to use bool since self is borrowed here
            }
        }
        if do_clear {
            self.clear_current();
        }
        self.namespace = namespace.map(|n| n.to_owned());
        self.set_prompt();
    }

    fn set_editor(&mut self, editor: &Option<String>) {
        self.click_config.editor = editor.clone();
    }

    fn set_terminal(&mut self, terminal: &Option<String>) {
        self.click_config.terminal = terminal.clone();
    }

    fn set_lastlist(&mut self, list: LastList) {
        self.last_objs = list;
    }

    fn clear_current(&mut self) {
        self.current_object = KObj::None;
        self.set_prompt();
    }

    fn set_current(&mut self, num: usize) {
        match self.last_objs {
            LastList::None => {
                println!("No active object list");
            }
            LastList::PodList(ref pl) => {
                if let Some(pod) = pl.items.get(num) {
                    let containers = pod.spec
                        .containers
                        .iter()
                        .map(|cspec| cspec.name.clone())
                        .collect();
                    self.current_object = KObj::Pod {
                        name: pod.metadata.name.clone(),
                        containers: containers,
                    };
                    self.current_object_namespace = pod.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::NodeList(ref nl) => {
                if let Some(name) = nl.items.get(num).map(|n| n.metadata.name.clone()) {
                    self.current_object = KObj::Node(name);
                    self.current_object_namespace = None;
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::DeploymentList(ref dl) => {
                if let Some(dep) = dl.items.get(num) {
                    self.current_object = KObj::Deployment(dep.metadata.name.clone());
                    self.current_object_namespace = dep.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::ServiceList(ref sl) => {
                if let Some(service) = sl.items.get(num) {
                    self.current_object = KObj::Service(service.metadata.name.clone());
                    self.current_object_namespace = service.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::ReplicaSetList(ref rsl) => {
                if let Some(ref replicaset) = rsl.items.get(num) {
                    match val_str_opt("/metadata/name", replicaset) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", replicaset);
                            self.current_object = KObj::ReplicaSet(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("ReplicaSet has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::ConfigMapList(ref cml) => {
                if let Some(ref cm) = cml.items.get(num) {
                    match val_str_opt("/metadata/name", cm) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", cm);
                            self.current_object = KObj::ConfigMap(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("ConfigMap has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::SecretList(ref sl) => {
                if let Some(ref secret) = sl.items.get(num) {
                    match val_str_opt("/metadata/name", secret) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", secret);
                            self.current_object = KObj::Secret(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("Secret has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            },
            LastList::JobList(ref jl) => {
                if let Some(ref job) = jl.items.get(num) {
                    match val_str_opt("/metadata/name", job) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", job);
                            self.current_object = KObj::Job(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("Job has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
        }
        self.set_prompt();
    }

    fn current_pod(&self) -> Option<&String> {
        if let KObj::Pod { ref name, .. } = self.current_object {
            Some(name)
        } else {
            None
        }
    }

    fn run_on_kluster<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Kluster) -> Result<R, KubeError>,
    {
        match self.kluster {
            Some(ref k) => match f(k) {
                Ok(r) => Some(r),
                Err(e) => {
                    println!("{}", e);
                    None
                }
            },
            None => {
                println!("Need to have an active context");
                None
            }
        }
    }

    /// Add a new task for the env to keep track of
    fn add_port_forward(&mut self, pf: PortForward) {
        self.port_forwards.push(pf);
    }

    fn get_port_forwards(&self) -> std::slice::Iter<PortForward> {
        self.port_forwards.iter()
    }

    fn get_port_forward(&mut self, i: usize) -> Option<&mut PortForward> {
        self.port_forwards.get_mut(i)
    }

    fn stop_port_forward(&mut self, i: usize) -> Result<(), std::io::Error> {
        if i < self.port_forwards.len() {
            let mut pf = self.port_forwards.remove(i);
            pf.child.kill()
        } else {
            Ok(())
        }
    }

    fn stop_all_forwards(&mut self) {
        for pf in self.port_forwards.iter_mut() {
            pf.child.kill().unwrap();
        }
        self.port_forwards = Vec::new();
    }
}

impl fmt::Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Env {{
  Current Context: {}
  Availble Contexts: {:?}
  Kubernetes Config File(s): {}
  Editor: {}
  Terminal: {}
}}",
            if let Some(ref k) = self.kluster {
                Red.bold().paint(k.name.as_str())
            } else {
                Red.paint("none")
            },
            self.config.contexts.keys(),
            self.config.source_file,
            self.click_config
                .editor
                .as_ref()
                .unwrap_or(&"<unset, will use $EDITOR>".to_owned()),
            self.click_config
                .terminal
                .as_ref()
                .unwrap_or(&"<unset, will use xterm>".to_owned()),
        )
    }
}

/// Things the can come after a | or > char in input
enum RightExpr<'a> {
    None,
    /// pipe to command with args
    Pipe(&'a str),
    /// redir to file
    Redir(&'a str),
    /// redir and append to
    Append(&'a str),
}

fn build_parser_expr<'a>(
    line: &'a str,
    range: Range<usize>,
) -> Result<(&'a str, RightExpr<'a>), KubeError> {
    let (click_cmd, rest) = line.split_at(range.start);

    let rbytes = rest.as_bytes();
    let sep = rbytes[0];
    let mut sepcnt = 0;

    while rbytes[sepcnt] == sep {
        sepcnt += 1;
    }

    if sep == b'|' && sepcnt > 1 {
        Err(KubeError::ParseErr(format!(
            "Parse error at {}: unexpected ||",
            range.start
        )))
    } else if sep == b'>' && sepcnt > 2 {
        Err(KubeError::ParseErr(format!(
            "Parse error at {}: unexpected >>",
            range.start
        )))
    } else {
        let right = match sep {
            b'|' => RightExpr::Pipe(&rest[sepcnt..]),
            b'>' => {
                if sepcnt == 1 {
                    RightExpr::Redir(&rest[sepcnt..].trim())
                } else {
                    RightExpr::Append(&rest[sepcnt..].trim())
                }
            }
            _ => {
                return Err(KubeError::ParseErr(format!(
                    "Parse error at {}: unexpected separator",
                    range.start
                )))
            }
        };
        Ok((click_cmd, right))
    }
}

fn parse_line<'a>(line: &'a str) -> Result<(&'a str, RightExpr<'a>), KubeError> {
    let parser = Parser::new(line);
    for (range, sep, _) in parser {
        match sep {
            '|' | '>' => return build_parser_expr(line, range),
            _ => {}
        }
    }
    Ok((line, RightExpr::None))
}

static SHELLP: &'static str = "Shell syntax can be used to redirect or pipe the output of click \
commands to files or other commands (like grep).\n
Examples:\n\
 # grep logs for ERROR:\n\
 logs my-cont | grep ERROR\n\n\
 # pass output of describe -j to jq, then grep for foo \n\
 describe -j | jq . | grep foo\n\n\
 # Save logs to logs.txt:\n\
 logs my-cont > /tmp/logs.txt\n\n\
 # Append log lines that contain \"foo bar\" to logs.txt\n\
 logs the-cont | grep \"foo bar\" >> /tmp/logs.txt";

fn main() {
    // Command line arg paring for click itself
    let matches = App::new("Click")
        .version(crate_version!())
        .author("Nick Lanham <nick@databricks.com>")
        .about("Command Line Interactive Contoller for Kubernetes")
        .arg(
            Arg::with_name("config_dir")
                .short("c")
                .long("config_dir")
                .value_name("DIR")
                .help("Specify the directory to find kubernetes and click configs")
                .takes_value(true),
        )
        .get_matches();

    let conf_dir = if let Some(dir) = matches.value_of("config_dir") {
        PathBuf::from(dir)
    } else {
        match dirs::home_dir() {
            Some(mut path) => {
                path.push(".kube");
                path
            }
            None => {
                println!("Can't get your home dir, please specify --config_dir");
                std::process::exit(-2);
            }
        }
    };

    let mut click_path = conf_dir.clone();
    click_path.push("click.config");
    let click_conf = ClickConfig::from_file(click_path.as_path().to_str().unwrap());

    let config_paths = env::var_os("KUBECONFIG")
        .map(|paths| {
            let split_paths = env::split_paths(&paths);
            split_paths.collect::<Vec<PathBuf>>()
        })
        .unwrap_or_else(|| {
            let mut config_path = conf_dir.clone();
            config_path.push("config");
            vec!(config_path)
        })
        .into_iter()
        .map(|config_file| config_file
            .as_path()
            .to_str()
            .unwrap_or("[CONFIG_PATH_EMPTY]")
            .to_owned())
        .collect::<Vec<_>>();

    let config = match Config::from_files(&config_paths) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "Could not load kubernetes config. Cannot continue.  Error was: {}",
                e.description()
            );
            return;
        }
    };

    let mut hist_path = conf_dir.clone();
    hist_path.push("click.history");

    let mut env = Env::new(config, click_conf);

    let mut commands: Vec<Box<Cmd>> = Vec::new();
    commands.push(Box::new(cmd::Quit::new()));
    commands.push(Box::new(cmd::Context::new()));
    commands.push(Box::new(cmd::Contexts::new()));
    commands.push(Box::new(cmd::Pods::new()));
    commands.push(Box::new(cmd::Nodes::new()));
    commands.push(Box::new(cmd::Deployments::new()));
    commands.push(Box::new(cmd::Services::new()));
    commands.push(Box::new(cmd::ReplicaSets::new()));
    commands.push(Box::new(cmd::ConfigMaps::new()));
    commands.push(Box::new(cmd::Namespace::new()));
    commands.push(Box::new(cmd::Logs::new()));
    commands.push(Box::new(cmd::Describe::new()));
    commands.push(Box::new(cmd::Exec::new()));
    commands.push(Box::new(cmd::Containers::new()));
    commands.push(Box::new(cmd::Events::new()));
    commands.push(Box::new(cmd::Clear::new()));
    commands.push(Box::new(cmd::EnvCmd::new()));
    commands.push(Box::new(cmd::SetCmd::new()));
    commands.push(Box::new(cmd::Delete::new()));
    commands.push(Box::new(cmd::UtcCmd::new()));
    commands.push(Box::new(cmd::Namespaces::new()));
    commands.push(Box::new(cmd::Secrets::new()));
    commands.push(Box::new(cmd::PortForward::new()));
    commands.push(Box::new(cmd::PortForwards::new()));
    commands.push(Box::new(cmd::Jobs::new()));

    let mut rl = Editor::<ClickCompleter>::new();
    rl.load_history(hist_path.as_path()).unwrap_or_default();

    // see comment on ClickCompleter::new for why a raw pointer is needed
    let raw_env: *const Env = &env;
    rl.set_completer(Some(ClickCompleter::new(&commands, raw_env)));

    while !env.quit {
        let mut writer = ClickWriter::new();
        let readline = rl.readline(env.prompt.as_str());
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                match parse_line(&line) {
                    Ok((left, right)) => {
                        // set up output
                        match right {
                            RightExpr::None => {} // do nothing
                            RightExpr::Pipe(cmd) => {
                                if let Err(e) = writer.setup_pipe(cmd) {
                                    println!("{}", e.description());
                                    continue;
                                }
                            }
                            RightExpr::Redir(filename) => match File::create(filename) {
                                Ok(out_file) => {
                                    writer.out_file = Some(out_file);
                                }
                                Err(ref e) => {
                                    println!("Can't open output file: {}", e);
                                    continue;
                                }
                            },
                            RightExpr::Append(filename) => {
                                match OpenOptions::new().append(true).create(true).open(filename) {
                                    Ok(out_file) => {
                                        writer.out_file = Some(out_file);
                                    }
                                    Err(ref e) => {
                                        println!("Can't open output file: {}", e);
                                        continue;
                                    }
                                }
                            }
                        }

                        let mut parts_vec: Vec<String> = Parser::new(left).map(|x| x.2).collect();
                        let mut parts = parts_vec.iter().map(|s| &**s);
                        if let Some(cmdstr) = parts.next() {
                            // There was something typed
                            if let Ok(num) = (cmdstr as &str).parse::<usize>() {
                                env.set_current(num);
                            } else if let Some(cmd) = commands.iter().find(|&c| c.is(cmdstr)) {
                                // found a matching command
                                cmd.exec(&mut env, &mut parts, &mut writer);
                            } else if cmdstr == "help" {
                                // help isn't a command as it needs access to the commands vec
                                if let Some(hcmd) = parts.next() {
                                    if let Some(cmd) = commands.iter().find(|&c| c.is(hcmd)) {
                                        cmd.print_help();
                                    } else {
                                        match hcmd {
                                            // match for meta topics
                                            "pipes" | "redirection" | "shell" => {
                                                println!("{}", SHELLP);
                                            }
                                            _ => {
                                                println!(
                                                    "I don't know anything about {}, sorry",
                                                    hcmd
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    println!(
                                        "Available commands (type 'help [COMMAND]' for details):"
                                    );
                                    let spacer = "                  ";
                                    for c in commands.iter() {
                                        println!(
                                            "  {}{}{}",
                                            c.get_name(),
                                            &spacer[0..(20 - c.get_name().len())],
                                            c.about()
                                        );
                                    }
                                    println!(
                                        "\nOther help topics (type 'help [TOPIC]' for details)"
                                    );
                                    println!(
                                        "  shell               Redirecting and piping click \
                                         output to shell commands"
                                    );
                                }
                            } else {
                                println!("Unknown command");
                            }
                        }

                        // reset output
                        writer.finish_output();
                    }
                    Err(err) => {
                        println!("{}", err);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {} // don't exit on Ctrl-C
            Err(_) => {
                break;
            }
        }
    }

    env.save_click_config(click_path);
    if let Err(e) = rl.save_history(hist_path.as_path()) {
        println!("Couldn't save command history: {}", e);
    }
    env.stop_all_forwards();
}
