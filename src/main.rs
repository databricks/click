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

use ansi_term::Colour::{Blue, Cyan, Red, Green, Yellow, Purple};
use clap::{Arg, App};
use rustyline::error::ReadlineError;
use rustyline::Editor;

use std::fmt;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cmd::Cmd;
use completer::ClickCompleter;
use config::{ClickConfig, Config};
use error::KubeError;
use kube::{Kluster, NodeList, PodList, DeploymentList, ServiceList};

/// An object we can have as a "current" thing
/// Includes pods and nodes at the moment
enum KObj {
    None,
    Pod(String),
    Node(String),
    Deployment(String),
    Service(String),
}

enum LastList {
    None,
    PodList(PodList),
    NodeList(NodeList),
    DeploymentList(DeploymentList),
    ServiceList(ServiceList),
}

/// An ongoing port forward
struct PortForward{
    child: Child,
    pod: String,
    ports: Vec<String>,
}

/// Keep track of our repl environment
pub struct Env {
    config: Config,
    quit: bool,
    kluster: Option<Kluster>,
    namespace: Option<String>,
    current_object: KObj,
    pub current_object_namespace: Option<String>,
    last_objs: LastList,
    pub ctrlcbool: Arc<AtomicBool>,
    port_forwards: Vec<PortForward>,
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
            current_object_namespace: None,
            last_objs: LastList::None,
            ctrlcbool: cbool,
            port_forwards: Vec::new(),
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
                                  KObj::Deployment(ref name) => Purple.bold().paint(name.as_str()),
                                  KObj::Service(ref name) => Cyan.bold().paint(name.as_str()),
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

    fn set_podlist(&mut self, pods: Option<PodList>) {
        if let Some(list) = pods {
            self.last_objs = LastList::PodList(list);
        } else {
            self.last_objs = LastList::None;
        }
    }

    fn set_nodelist(&mut self, nodes: Option<NodeList>) {
        if let Some(list) = nodes {
            self.last_objs = LastList::NodeList(list);
        } else {
            self.last_objs = LastList::None;
        }
    }

    fn set_deplist(&mut self, deployments: Option<DeploymentList>) {
        if let Some(list) = deployments {
            self.last_objs = LastList::DeploymentList(list);
        } else {
            self.last_objs = LastList::None;
        }
    }

    fn set_servicelist(&mut self, services: Option<ServiceList>) {
        if let Some(list) = services {
            self.last_objs = LastList::ServiceList(list);
        } else {
            self.last_objs = LastList::None;
        }
    }

    fn clear_current(&mut self) {
        self.current_object = KObj::None;
        self.set_prompt();
    }

    fn set_current(&mut self, num: usize) {
        match self.last_objs {
            LastList::None => {
                println!("No active object list");
            },
            LastList::PodList(ref pl) => {
                if let Some(pod) = pl.items.get(num) {
                    self.current_object = KObj::Pod(pod.metadata.name.clone());
                    self.current_object_namespace = pod.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            },
            LastList::NodeList(ref nl) => {
                if let Some(name) = nl.items.get(num).map(|n| n.metadata.name.clone()) {
                    self.current_object = KObj::Node(name);
                    self.current_object_namespace = None;
                } else {
                    self.current_object = KObj::None;
                }
            },
            LastList::DeploymentList(ref dl) => {
                if let Some(dep) = dl.items.get(num) {
                    self.current_object = KObj::Deployment(dep.metadata.name.clone());
                    self.current_object_namespace = dep.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            },
            LastList::ServiceList(ref sl) => {
                if let Some(service) = sl.items.get(num) {
                    self.current_object = KObj::Service(service.metadata.name.clone());
                    self.current_object_namespace = service.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            },
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

    /// Add a new task for the env to keep track of
    fn add_port_forward(&mut self, pf: PortForward) {
        self.port_forwards.push(pf);
    }

    fn get_port_forwards(&self) -> std::slice::Iter<PortForward> {
        self.port_forwards.iter()
    }

    fn get_port_forward(&self, i: usize) -> Option<&PortForward> {
        self.port_forwards.get(i)
    }

    fn stop_port_forward(&mut self, i: usize) -> Result<(), std::io::Error> {
        if i < self.port_forwards.len() {
            let mut pf = self.port_forwards.remove(i);
            pf.child.kill()
        } else {
            Ok(())
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

    let conf_dir =
        if let Some(dir) = matches.value_of("config_dir") {
            PathBuf::from(dir)
        } else {
            match std::env::home_dir() {
                Some(mut path) => {
                    path.push(".kube");
                    path
                },
                None => {
                    println!("Can't get your home dir, please specify --config_dir");
                    std::process::exit(-2);
                }
            }
        };

    let mut click_path = conf_dir.clone();
    click_path.push("click.config");
    let mut click_conf = ClickConfig::from_file(click_path.as_path().to_str().unwrap());

    let mut config_path = conf_dir.clone();
    config_path.push("config");

    let config = Config::from_file(config_path.as_path().to_str().unwrap());

    let mut hist_path = conf_dir.clone();
    hist_path.push("click.history");

    let mut env = Env::new(config);
    env.set_namespace(click_conf.namespace.as_ref().map(|x| &**x));
    env.set_context(click_conf.context.as_ref().map(|x| &**x));

    let mut commands: Vec<Box<Cmd>> = Vec::new();
    commands.push(Box::new(cmd::Quit::new()));
    commands.push(Box::new(cmd::Context::new()));
    commands.push(Box::new(cmd::Pods::new()));
    commands.push(Box::new(cmd::Nodes::new()));
    commands.push(Box::new(cmd::Deployments::new()));
    commands.push(Box::new(cmd::Services::new()));
    commands.push(Box::new(cmd::Namespace::new()));
    commands.push(Box::new(cmd::Logs::new()));
    commands.push(Box::new(cmd::Describe::new()));
    commands.push(Box::new(cmd::Exec::new()));
    commands.push(Box::new(cmd::Containers::new()));
    commands.push(Box::new(cmd::Events::new()));
    commands.push(Box::new(cmd::Clear::new()));
    commands.push(Box::new(cmd::EnvCmd::new()));
    commands.push(Box::new(cmd::Delete::new()));
    commands.push(Box::new(cmd::UtcCmd::new()));
    commands.push(Box::new(cmd::Namespaces::new()));
    commands.push(Box::new(cmd::PortForward::new()));
    commands.push(Box::new(cmd::PortForwards::new()));

    let mut rl = Editor::<ClickCompleter>::new();
    rl.load_history(hist_path.as_path()).unwrap_or_default();

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
                            let spacer = "                  ";
                            for c in commands.iter() {
                                println!("  {}{}{}", c.get_name(), &spacer[0..(20-c.get_name().len())], c.about());
                            }
                        }
                    }
                    else {
                        println!("Unknown command");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => { }, // don't exit on Ctrl-C
            Err(_)   => {
                break;
            }
        }
    }
    click_conf.from_env(&env);
    click_conf.save_to_file(click_path.as_path().to_str().unwrap()).unwrap();
    if let Err(e) = rl.save_history(hist_path.as_path()) {
        println!("Couldn't save command history: {}", e);
    }
}
