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

#[macro_use] extern crate prettytable;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;

extern crate ansi_term;
extern crate clap;
extern crate chrono;
extern crate ctrlc;
extern crate hyper;
extern crate hyper_rustls;
extern crate regex;
extern crate rustls;
extern crate rustyline;
extern crate serde;
extern crate serde_json;
extern crate serde_yaml;

mod certs;
mod cmd;
mod completer;
mod config;
mod error;
mod kube;

use ansi_term::Colour::{Blue, Red, Green, Yellow};
use clap::{Arg, App};
use rustyline::Editor;

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cmd::Cmd;
use completer::ClickCompleter;
use config::{ClickConfig, Config};
use error::KubeError;
use kube::{Kluster, NodeList, PodList};

/// An object we can have as a "current" thing
/// Includes pods and nodes at the moment
enum KObj {
    None,
    Pod(String),
    Node(String),
}

/// Keep track of our repl environment
pub struct Env {
    config: Config,
    quit: bool,
    kluster: Option<Kluster>,
    namespace: Option<String>,
    current_object: KObj,
    last_pods: Option<PodList>,
    last_nodes: Option<NodeList>,
    pub ctrlcbool: Arc<AtomicBool>,
    prompt: String,
}

impl Env {
    fn new(config: Config) -> Env {
        let cbool = Arc::new(AtomicBool::new(false));
        let r = cbool.clone();
        ctrlc::set_handler(move || {
            r.store(true, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
        Env {
            config: config,
            quit: false,
            kluster: None,
            namespace: None,
            current_object: KObj::None,
            last_pods: None,
            last_nodes: None,
            ctrlcbool: cbool,
            prompt: format!("[{}] [{}] [{}] > ", Red.paint("none"), Green.paint("none"), Yellow.paint("none")),
        }
    }

    // sets the prompt string based on current settings
    fn set_prompt(&mut self) {
        self.prompt = format!("[{}] [{}] [{}] > ",
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
                                  KObj::Pod(ref name) => Yellow.bold().paint(name.as_str()),
                                  KObj::Node(ref name) => Blue.bold().paint(name.as_str()),
                              }
        );

    }

    fn set_context(&mut self, ctx: Option<&str>) {
        match ctx {
            Some(cname) => {
                self.kluster = match self.config.cluster_for_context(cname) {
                    Ok(k) => {
                        Some(k)
                    },
                    Err(e) => {
                        println!("[Warning] Couldn't find context, no active context: {}", e);
                        None
                    }
                };
                self.set_prompt();
            },
            None => {} // no-op
        }
    }

    fn set_namespace(&mut self, namespace: Option<&str>) {
        self.namespace = namespace.map(|n| n.to_owned());
        self.set_prompt();
    }

    fn set_podlist(&mut self, pods: Option<PodList>) {
        self.last_pods = pods;
        self.last_nodes = None;
    }

    fn set_nodelist(&mut self, nodes: Option<NodeList>) {
        self.last_pods = None;
        self.last_nodes = nodes;
    }

    fn clear_current(&mut self) {
        self.current_object = KObj::None;
        self.set_prompt();
    }

    fn set_current(&mut self, num: usize) {
        if let Some(ref pl) = self.last_pods {
            if let Some(name) = pl.items.get(num).map(|p| p.metadata.name.clone()) {
                self.current_object = KObj::Pod(name);
            } else {
                self.current_object = KObj::None;
            }
        } else if let Some(ref nl) = self.last_nodes {
            if let Some(name) = nl.items.get(num).map(|n| n.metadata.name.clone()) {
                self.current_object = KObj::Node(name);
            } else {
                self.current_object = KObj::None;
            }
        } else {
            println!("No active pod or node list");
        }
        self.set_prompt();
    }

    fn current_pod(&self) -> Option<&String> {
        if let KObj::Pod(ref name) = self.current_object {
            Some(name)
        } else {
            None
        }
    }

    fn run_on_kluster<F, R>(&self, f: F) -> Option<R>
        where F: FnOnce(&Kluster) -> Result<R, KubeError> {

        match self.kluster {
            Some(ref k) => {
                match f(k) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        println!("{}", e);
                        None
                    },
                }
            },
            None => {
                println!("Need to have an active context");
                None
            }
        }
    }
}

impl fmt::Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Env {{
  Current Context: {}
  Availble Contexts: {:?}
  Kubernetes Config File: {}
}}",
               if let Some(ref k) = self.kluster {
                   Red.bold().paint(k.name.as_str())
               } else {
                   Red.paint("none")
               },
               self.config.contexts.keys(),
               self.config.source_file,
        )
    }
}

fn main() {
    // Command line arg paring for click itself
    let matches = App::new("Click")
        .version("0.1")
        .author("Nick Lanham <nick@databricks.com>")
        .about("Command Line Interactive Contoller for Kubernetes")
        .arg(Arg::with_name("config_dir")
             .short("c")
             .long("config_dir")
             .value_name("DIR")
             .help("Specify the directory to find kubernetes and click configs")
             .takes_value(true))
        .get_matches();

    let mut conf_dir =
        if let Some(dir) = matches.value_of("config_dir") {
            PathBuf::from(dir)
        } else {
            match std::env::home_dir() {
                Some(path) => path,
                None => {
                    println!("Can't get your home dir, please specify --config_dir");
                    std::process::exit(-2);
                }
            }
        };

    let mut click_path = conf_dir.clone();
    click_path.push(".kube");
    click_path.push("click.config");
    let mut click_conf = ClickConfig::from_file(click_path.as_path().to_str().unwrap());

    conf_dir.push(".kube");
    conf_dir.push("config");

    let config = Config::from_file(conf_dir.as_path().to_str().unwrap());

    let mut env = Env::new(config);
    env.set_namespace(click_conf.namespace.as_ref().map(|x| &**x));
    env.set_context(click_conf.context.as_ref().map(|x| &**x));

    let mut commands: Vec<Box<Cmd>> = Vec::new();
    commands.push(Box::new(cmd::Quit::new()));
    commands.push(Box::new(cmd::Context::new()));
    commands.push(Box::new(cmd::Pods::new()));
    commands.push(Box::new(cmd::Nodes::new()));
    commands.push(Box::new(cmd::Deployments::new()));
    commands.push(Box::new(cmd::Namespace::new()));
    commands.push(Box::new(cmd::Logs::new()));
    commands.push(Box::new(cmd::Describe::new()));
    commands.push(Box::new(cmd::Exec::new()));
    commands.push(Box::new(cmd::Containers::new()));
    commands.push(Box::new(cmd::Events::new()));
    commands.push(Box::new(cmd::Clear::new()));
    commands.push(Box::new(cmd::EnvCmd::new()));
    commands.push(Box::new(cmd::Delete::new()));

    let mut rl = Editor::<ClickCompleter>::new();

    // see comment on ClickCompleter::new for why a raw pointer is needed
    let raw_env: *const Env = &env;
    rl.set_completer(Some(ClickCompleter::new(&commands, raw_env)));
    while !env.quit {
        let readline = rl.readline(env.prompt.as_str());
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                let mut parts = line.split_whitespace();
                if let Some(cmdstr) = parts.next() {
                    // There was something typed
                    if let Ok(num) = cmdstr.parse::<usize>() {
                        env.set_current(num);
                    }
                    else if let Some(cmd) = commands.iter().find(|&c| c.is(cmdstr)) {
                        // found a matching command
                        cmd.exec(&mut env, &mut parts);
                    }
                    else if cmdstr == "help" {
                        // help isn't a command as it needs access to the commands vec
                        if let Some(hcmd) = parts.next() {
                            if let Some(cmd) = commands.iter().find(|&c| c.is(hcmd)) {
                                cmd.print_help();
                            } else {
                                println!("I don't know anything about {}, sorry", hcmd);
                            }
                        } else {
                            println!("Available commands (type 'help command' for details):");
                            let spacer = "          ";
                            for c in commands.iter() {
                                println!("  {}{}{}", c.get_name(), &spacer[0..(12-c.get_name().len())], c.about());
                            }
                        }
                    }
                    else {
                        println!("Unknown command");
                    }
                }
            }
            Err(_)   => {
                break;
            }
        }
    }
    click_conf.from_env(&env);
    click_conf.save_to_file(click_path.as_path().to_str().unwrap()).unwrap();
}
