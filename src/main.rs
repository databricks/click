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


#[macro_use]
extern crate serde_derive;

extern crate ansi_term;

extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;

extern crate serde;
extern crate serde_json;
extern crate serde_yaml;

extern crate rustyline;

mod cmd;
mod config;
mod error;
mod kube;

use ansi_term::Colour::{Red, Green, Yellow};

use cmd::Cmd;
use config::{ClickConfig, Config};
use kube::{PodList, Kluster};

/// Keep track of our repl environment
pub struct Env {
    config: Config,
    kluster: Option<Kluster>,
    namespace: Option<String>,
    current_pod: Option<String>,
    last_pods: Option<PodList>,
    prompt: String,
}

impl Env {
    fn new(config: Config) -> Env {
        Env {
            config: config,
            kluster: None,
            namespace: None,
            current_pod: None,
            last_pods: None,
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
                              if let Some(ref p) = self.current_pod {
                                  Yellow.bold().paint(p.as_str())
                              } else {
                                  Yellow.paint("none")
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

    fn set_podlist(&mut self, pods: Option<PodList>, print: bool) {
        self.last_pods = pods;
        if print {
            match self.last_pods {
                Some(ref pl) => {
                    for (i,pod) in pl.items.iter().enumerate() {
                        println!("{}\t{}", i, pod.metadata.name);
                    }
                }
                None => {
                    println!("(podlist now empty)");
                }
            }
        }
    }

    fn set_current_pod(&mut self, num: usize) {
        if let Some(ref pl) = self.last_pods {
            self.current_pod = pl.items.get(num).map(|p| p.metadata.name.clone());
        } else {
            println!("No active pod list");
        }
        self.set_prompt();
    }

    fn run_on_kluster<F, R>(&self, f: F) -> Option<R>
        where F: FnOnce(&Kluster) -> R {

        match self.kluster {
            Some(ref k) => {
                Some(f(k))
            },
            None => {
                println!("Need to have an active context");
                None
            }
        }
    }
}

fn main() {
    let mut conf_dir = match std::env::home_dir() {
        Some(path) => path,
        None => {
            println!("Can't get your home dir, please specify a config dir");
            // TODO: Allow to specify
            std::process::exit(-2);
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
    commands.push(Box::new(cmd::Quit));
    commands.push(Box::new(cmd::Context));
    commands.push(Box::new(cmd::Pods));
    commands.push(Box::new(cmd::LPods));
    commands.push(Box::new(cmd::Namespace));
    commands.push(Box::new(cmd::Logs));
    commands.push(Box::new(cmd::Describe));

    let mut rl = rustyline::Editor::<()>::new();
    loop {
        let readline = rl.readline(env.prompt.as_str());
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                let mut parts = line.split_whitespace();
                if let Some(cmdstr) = parts.next() {
                    // There was something typed
                    if let Ok(num) = cmdstr.parse::<usize>() {
                        env.set_current_pod(num);
                    }
                    else if let Some(cmd) = commands.iter().find(|&c| c.is(cmdstr)) {
                        // found a matching command
                        if cmd.exec(&mut env, &mut parts) {
                            break;
                        }
                    }
                    else if cmdstr == "help" {
                        // help isn't a command as it needs access to the commands vec
                        if let Some(hcmd) = parts.next() {
                            if let Some(cmd) = commands.iter().find(|&c| c.is(hcmd)) {
                                println!("{}", cmd.help());
                            } else {
                                println!("I don't know anything about {}, sorry", hcmd);
                            }
                        } else {
                            println!("Available commands (type 'help command' for details):");
                            for c in commands.iter() {
                                println!("  {}",c.get_name());
                            }
                        }
                    }
                    else {
                        println!("Unknown command");
                    }
                } else {
                    println!("No command");
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
