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

//!  The commands one can run from the repl

use ::Env;

use serde_json::Value;

use std::iter::Iterator;
use std::io::{BufRead,BufReader};

use kube::PodList;

pub trait Cmd {
    // break if returns true
    fn exec(&self, &mut Env, &mut Iterator<Item=&str>) -> bool;
    fn is(&self, &str) -> bool;
    fn get_name(&self) -> &'static str;
    fn help(&self) -> &'static str;
}

pub struct Quit;
impl Cmd for Quit {
    fn exec(&self, _:&mut Env, _:&mut Iterator<Item=&str>) -> bool {
        true
    }

    fn is(&self, l: &str) -> bool {
        l == "q" || l == "quit"
    }

    fn get_name(&self) -> &'static str {
        "quit"
    }

    fn help(&self) -> &'static str {
        "Quit Click"
    }
}


pub struct Context;
impl Cmd for Context {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        env.set_context(args.next());
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "ctx" || l == "context"
    }

    fn get_name(&self) -> &'static str {
        "context"
    }

    fn help(&self) -> &'static str {
        "Set the context"
    }
}

pub struct Namespace;
impl Cmd for Namespace {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        env.set_namespace(args.next());
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "ns" || l == "namespace"
    }

    fn get_name(&self) -> &'static str {
        "namespace"
    }

    fn help(&self) -> &'static str {
        "Set the current namespace."
    }
}


pub struct Pods;
impl Cmd for Pods {
    fn exec(&self, env: &mut Env, _: &mut Iterator<Item=&str>) -> bool {
        let urlstr = if let Some(ref ns) = env.namespace {
            format!("/api/v1/namespaces/{}/pods", ns)
        } else {
            "/api/v1/pods".to_owned()
        };

        let pl: Option<PodList> = env.run_on_kluster(|k| {
            k.get(urlstr.as_str()).unwrap()
        });
        env.set_podlist(pl, true);
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "pods"
    }

    fn get_name(&self) -> &'static str {
        "pods"
    }

    fn help(&self) -> &'static str {
        "Get all pods in current context"
    }
}

pub struct LPods;
impl Cmd for LPods {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        if let Some(filt) = args.next() {
            let urlstr = if let Some(ref ns) = env.namespace {
                format!("/api/v1/namespaces/{}/pods?labelSelector={}", ns, filt)
            } else {
                format!("/api/v1/pods?labelSelector={}", filt)
            };

            let pl: Option<PodList> = env.run_on_kluster(|k| {
                k.get(urlstr.as_str()).unwrap()
            });
            env.set_podlist(pl, true);
        } else {
            println!("Missing arg");
        }
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "lpods"
    }

    fn get_name(&self) -> &'static str {
        "lpods"
    }

    fn help(&self) -> &'static str {
        "Get pods with the specified lable (example: app=kinesis2prom)"
    }
}


pub struct Logs;
impl Cmd for Logs {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
            if let Some(cont) = args.next() {
                let url = format!("/api/v1/namespaces/{}/pods/{}/log?container={}", ns, pod, cont);
                let logs_reader = env.run_on_kluster(|k| {
                    k.get_read(url.as_str()).unwrap()
                });
                let mut reader = BufReader::new(logs_reader.unwrap());
                let mut line = String::new();
                loop {
                    if let Ok(amt) = reader.read_line(&mut line) {
                        if amt > 0 {
                            print!("{}", line); // newlines already in line
                            line.clear();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                println!("Must specify a container")
            }
        }}
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "logs"
    }

    fn get_name(&self) -> &'static str {
        "logs"
    }

    fn help(&self) -> &'static str {
        "Get logs for active pod"
    }
}

pub struct Describe;
impl Describe {
    fn format_value(&self, v: Value) -> String {
        let metadata = v.get("metadata").unwrap();
        let spec = v.get("spec").unwrap();
        let status = v.get("status").unwrap();
        format!("Name:\t\t{}\n\
Namespace:\t{}\n\
Node:\t\t{}\n\
Created at:\t{}\n\
Status:\t\t{}",
                metadata.get("name").unwrap(),
                metadata.get("namespace").unwrap(),
                spec.get("nodeName").unwrap(),
                metadata.get("creationTimestamp").unwrap(),
                status.get("phase").unwrap(),
        )
    }
}
impl Cmd for Describe {
    fn exec(&self, env: &mut Env, _: &mut Iterator<Item=&str>) -> bool {
        if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
            let url = format!("/api/v1/namespaces/{}/pods/{}", ns, pod);
            let pod_value = env.run_on_kluster(|k| {
                k.get_value(url.as_str()).unwrap()
            });
            println!("{}", self.format_value(pod_value.unwrap()));
        }}
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "describe"
    }

    fn get_name(&self) -> &'static str {
        "describe"
    }

    fn help(&self) -> &'static str {
        "Describe the active pod"
    }
}

