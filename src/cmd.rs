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

use ansi_term::ANSIString;
use ansi_term::Colour::{Blue, Green, Red, Yellow};
use clap::{Arg, App, AppSettings};
use chrono::DateTime;
use chrono::offset::utc::UTC;
use chrono::offset::local::Local;
use serde_json::Value;
use regex::Regex;

use std::cell::RefCell;
use std::iter::Iterator;
use std::io::{BufRead,BufReader};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kube::{Event, EventList, PodList, NodeList, NodeCondition};

pub trait Cmd {
    // break if returns true
    fn exec(&self, &mut Env, &mut Iterator<Item=&str>) -> bool;
    fn is(&self, &str) -> bool;
    fn get_name(&self) -> &'static str;
    fn help(&self) -> &'static str;
}

fn color_phase(phase: &str) -> ANSIString {
    match phase {
        "Pending" | "Running" => Green.paint(phase),
        "Succeeded" => Blue.paint(phase),
        "Failed" => Red.paint(phase),
        "Unknown" => Yellow.paint(phase),
        _ => Yellow.paint(phase),
    }
}

fn time_since(date: DateTime<UTC>) -> String {
    let now = UTC::now();
    let diff = now.signed_duration_since(date);
    if diff.num_days() > 0 {
        format!("{}d", diff.num_days())
    } else {
        format!("{}h", diff.num_hours())
    }
}

fn print_podlist(podlist: &PodList) {
    let mut max_len = 0;
    for pod in podlist.items.iter() {
        if pod.metadata.name.len() > max_len {
            max_len = pod.metadata.name.len();
        }
    }
    max_len+=2;
    let spacer = String::from_utf8(vec![b' '; max_len]).unwrap();
    let sep = String::from_utf8(vec![b'-'; max_len+12]).unwrap();

    println!("###  Name{}Phase",&spacer[0..(max_len-4)]);
    println!("{}",sep);

    for (i,pod) in podlist.items.iter().enumerate() {
        let space = max_len - pod.metadata.name.len();
        println!("{:>3}  {}{}{}", i, pod.metadata.name, &spacer[0..space], color_phase(pod.status.phase.as_str()));
    }
}

fn print_nodelist(nodelist: &NodeList) {
    for node in nodelist.items.iter() {
        let readycond: Vec<&NodeCondition> = node.status.conditions.iter().filter(|c| c.typ == "Ready").collect();
        let state =
            if let Some(cond) = readycond.get(0) {
                if cond.status == "True" {
                    Green.paint("Ready")
                } else {
                    Red.paint("Not Ready")
                }
            } else {
                Yellow.paint("Unknown")
            };
        let unsched =
            if let Some(b) = node.spec.unschedulable {
                if b {
                    ",SchedulingDisabled"
                } else {
                    "\t\t\t"
                }
            } else {
                "\t\t\t"
            };
        println!("{}\t{}{}\t{}", node.metadata.name, state, unsched, time_since(node.metadata.creation_timestamp.unwrap()));
    }
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
        if let Some(ref l) = pl {
            print_podlist(&l);
        }
        env.set_podlist(pl);
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
            if let Some(ref l) = pl {
                print_podlist(l);
            }
            env.set_podlist(pl);
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

pub struct GPods;
impl Cmd for GPods {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        if let Some(pattern) = args.next() {
            if let Ok(regex) = Regex::new(pattern) {
                let urlstr = if let Some(ref ns) = env.namespace {
                    format!("/api/v1/namespaces/{}/pods", ns)
                } else {
                    "/api/v1/pods".to_owned()
                };

                let pl: Option<PodList> = env.run_on_kluster(|k| {
                    k.get(urlstr.as_str()).unwrap()
                });
                if let Some(l) = pl {
                    let filtered = l.items.into_iter().filter(|x| regex.is_match(x.metadata.name.as_str())).collect();
                    let new_podlist = PodList {
                        items: filtered
                    };
                    print_podlist(&new_podlist);
                    env.set_podlist(Some(new_podlist));
                } else {
                    env.set_podlist(pl);
                }
            } else {
                println!("Invalid pattern: {}", pattern);
            }
        } else {
            println!("Missing arg");
        }
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "gpods"
    }

    fn get_name(&self) -> &'static str {
        "gpods"
    }

    fn help(&self) -> &'static str {
        "Get pods filtered by specified regex"
    }
}


pub struct Logs {
    clap: RefCell<App<'static, 'static>>,
}

impl Logs {
    pub fn new() -> Logs {
        let clap = App::new("logs")
            .about("Get logs from a container in the current pod")
            .setting(AppSettings::NoBinaryName)
            .setting(AppSettings::DisableVersion)
            .arg(Arg::with_name("container")
                 .help("Specify which container to get logs from")
                 .required(true)
                 .index(1))
            .arg(Arg::with_name("follow")
                 .short("f")
                 .long("follow")
                 .help("Follow the logs as new records arrive (stop with ^D)")
                 .takes_value(false));
        Logs {
            clap: RefCell::new(clap),
        }
    }
}

impl Cmd for Logs {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        match self.clap.borrow_mut().get_matches_from_safe_borrow(args) {
            Ok(matches) => {
                let cont = matches.value_of("container").unwrap(); // required so unwrap safe
                let follow = matches.is_present("follow");
                if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
                    let mut url = format!("/api/v1/namespaces/{}/pods/{}/log?container={}", ns, pod, cont);
                    if follow {
                        url.push_str("&follow=true");
                    }
                    let logs_reader = env.run_on_kluster(|k| {
                        k.get_read(url.as_str(), Some(Duration::new(1, 0))).unwrap()
                    });
                    let mut reader = BufReader::new(logs_reader.unwrap());
                    let mut line = String::new();

                    env.ctrlcbool.store(false, Ordering::SeqCst);
                    while !env.ctrlcbool.load(Ordering::SeqCst) {
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
                }}
            },
            Err(err) => {
                println!("{}", err.message);
            }
        }
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
                Green.paint(status.get("phase").unwrap().as_str().unwrap()),
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


pub struct Exec;
impl Cmd for Exec {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        if let Some(cmd) = args.next() {
            if let (Some(ref kluster), Some(ref ns), Some(ref pod)) = (env.kluster.as_ref(), env.namespace.as_ref(), env.current_pod.as_ref()) {
                let status = Command::new("kubectl")
                    .arg("--namespace")
                    .arg(ns)
                    .arg("--context")
                    .arg(&kluster.name)
                    .arg("exec")
                    .arg("-it")
                    .arg(pod)
                    .arg(cmd)
                    .status()
                    .expect("failed to execute kubectl");
                if !status.success() {
                    println!("kubectl exited abnormally");
                }
            } else {
                println!("No active kluster, or namespace, or pod");
            }
        } else {
            println!("No command specified")
        }
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "exec"
    }

    fn get_name(&self) -> &'static str {
        "exec"
    }

    fn help(&self) -> &'static str {
        "exec specified command on active pod"
    }
}


pub struct Containers;

impl Containers {
    fn format_value(&self, v: Value) -> String {
        let mut buf = String::new();
        if let Some(vconts) = v.pointer("/status/containerStatuses") {
            // have that element
            if let Some(conts) = vconts.as_array() {
                for cont in conts {
                    buf.push_str(format!("Name:\t{}\n",cont.get("name").unwrap().as_str().unwrap()).as_str());
                    if let Some(o) = cont.get("state").unwrap().as_object() {
                        buf.push_str(format!(" State:\t{}\n", Green.paint(o.keys().next().unwrap().as_str())).as_str());
                    } else {
                        buf.push_str(" State:\tUnknown\n");
                    }
                    buf.push('\n');
                }
            }
        } else if let Some(sconts) = v.pointer("/spec/containers") {
            if let Some(conts) = sconts.as_array() {
                for cont in conts {
                    buf.push_str(format!("Name:\t{}\n", cont.get("name").unwrap().as_str().unwrap()).as_str());
                }
            }
        } else {
            buf.push_str("Unable to find any containers.");
        }
        buf
    }
}

impl Cmd for Containers {
    fn exec(&self, env: &mut Env, _args: &mut Iterator<Item=&str>) -> bool {
        if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
            let url = format!("/api/v1/namespaces/{}/pods/{}", ns, pod);
            let pod_value = env.run_on_kluster(|k| {
                k.get_value(url.as_str()).unwrap()
            });
            println!("{}", self.format_value(pod_value.unwrap()));
        } else {
            println!("No active pod");
        }} else {
            println!("No active namespace");
        }
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "containers" || l == "conts"
    }

    fn get_name(&self) -> &'static str {
        "containers"
    }

    fn help(&self) -> &'static str {
        "list containers on active pod"
    }
}


pub struct Events;

impl Events {
    fn format_event(&self, event: &Event) -> String {
        format!("{} - {}\n count: {}\n reason: {}\n",
                event.last_timestamp.with_timezone(&Local),
                event.message,
                event.count,
                event.reason)
    }
}

impl Cmd for Events {
    fn exec(&self, env: &mut Env, _args: &mut Iterator<Item=&str>) -> bool {
        if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
            let url = format!("/api/v1/namespaces/{}/events?fieldSelector=involvedObject.name={},involvedObject.namespace={}",
                              ns,pod,ns);
            let oel: Option<EventList> = env.run_on_kluster(|k| {
                k.get(url.as_str()).unwrap()
            });
            if let Some(el) = oel {
                if el.items.len() > 0 {
                    for e in el.items.iter() {
                        println!("{}",self.format_event(e));
                    }
                } else {
                    println!("No events");
                }
            } else {
                println!("Failed to fetch events");
            }
        } else {
            println!("No active pod");
        }} else {
            println!("No active namespace");
        }
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "events"
    }

    fn get_name(&self) -> &'static str {
        "events"
    }

    fn help(&self) -> &'static str {
        "Get events for the active pod"
    }
}

pub struct Nodes {
    clap: RefCell<App<'static, 'static>>,
}

impl Nodes {
    pub fn new() -> Nodes {
        let clap = App::new("nodes")
            .about("Get nodes in current namespace")
            .setting(AppSettings::NoBinaryName)
            .setting(AppSettings::DisableVersion);
        Nodes {
            clap: RefCell::new(clap),
        }
    }
}

impl Cmd for Nodes {
    fn exec(&self, env: &mut Env, args: &mut Iterator<Item=&str>) -> bool {
        match self.clap.borrow_mut().get_matches_from_safe_borrow(args) {
            Ok(_matches) => {
                let url = "/api/v1/nodes";
                let nl: Option<NodeList> = env.run_on_kluster(|k| {
                    k.get(url).unwrap()
                });
                if let Some(ref n) = nl {
                    print_nodelist(&n);
                }
            },
            Err(err) => {
                println!("{}", err.message);
            }
        }
        false
    }

    fn is(&self, l: &str) -> bool {
        l == "nodes"
    }

    fn get_name(&self) -> &'static str {
        "nodes"
    }

    fn help(&self) -> &'static str {
        "get nodes"
    }
}
