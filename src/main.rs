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

extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;

extern crate serde;
extern crate serde_json;
extern crate serde_yaml;

extern crate rustyline;

mod config;
mod error;
mod kube;

use config::Config;
use kube::{PodList, Kluster};

/// Keep track of our repl environment
struct Env {
    config: Config,
    kluster: Option<Kluster>,
    last_pods: Option<PodList>,
    prompt: String,
}

impl Env {
    fn new(config: Config) -> Env {
        Env {
            config: config,
            kluster: None,
            last_pods: None,
            prompt: "[none] > ".to_owned()
        }
    }

    fn set_context(&mut self, ctx: Option<&str>) {
        match ctx {
            Some(cname) => {
                self.kluster = match self.config.cluster_for_context(cname) {
                    Ok(k) => {
                        self.prompt = format!("[{}] > ", cname);
                        Some(k)
                    },
                    Err(e) => {
                        println!("Could not parse config: {}", e);
                        std::process::exit(-1);
                    }
                }
            },
            None => {
                println!("Must provide a context name");
            }
        }
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
    let config = Config::from_file("/home/nick/.kube/config");

    let mut env = Env::new(config);

    //let mut kluster: Option<Kluster> = None;
    //let mut prompt = "[none]> ".to_owned();

    let mut rl = rustyline::Editor::<()>::new();
    loop {
        let readline = rl.readline(env.prompt.as_str());
        match readline {
            Ok(line) => {
                let mut parts = line.split_whitespace();
                match parts.next() {
                    Some("quit") | Some("q") => {
                        println!("Goodbye");
                        break
                    },
                    Some("context") | Some("ctx") => {
                        env.set_context(parts.next());
                    },
                    Some("pods") => {
                        let pl: Option<PodList> = env.run_on_kluster(|k| {
                            k.get("/api/v1/pods").unwrap()
                        });
                        env.set_podlist(pl, true);
                    },
                    Some("lpods") => {
                        if let Some(filt) = parts.next() {
                            let pl: Option<PodList> = env.run_on_kluster(|k| {
                                k.get(format!("/api/v1/pods?labelSelector={}", filt).as_str()).unwrap()
                            });
                            env.set_podlist(pl, true);
                        } else {
                            println!("Missing arg");
                        }
                    },

                    Some(x) => println!("l: {}",x),
                    None => println!("No command"),
                }
            }
            Err(_)   => {
                println!("Goodbye");
                break;
            }
        }
    }

    // let pods: PodList = kluster.get("/api/v1/pods?labelSelector=app=node-exporter").unwrap();
    // for pod in pods.items.iter() {
    //     println!("{}", pod.metadata.name);
    // }
}
