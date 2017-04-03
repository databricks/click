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
use clap::{Arg, ArgMatches, App, AppSettings};
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
    fn print_help(&self);
}

/// Get the start of a clap object
fn start_clap(name: &'static str, about: &'static str) -> App<'static, 'static> {
    App::new(name)
        .about(about)
        .setting(AppSettings::NoBinaryName)
        .setting(AppSettings::DisableVersion)
}

/// Run specified closure with the given matches, or print error.  Return true if execed, false on err
fn exec_match<F>(clap: &RefCell<App<'static, 'static>>, env: &mut Env, args: &mut Iterator<Item=&str>, func: F) -> bool
    where F: FnOnce(ArgMatches,&mut Env) -> () {
    match clap.borrow_mut().get_matches_from_safe_borrow(args) {
        Ok(matches) => {
            func(matches, env);
            true
        },
        Err(err) => {
            println!("{}", err.message);
            false
        }
    }
}

/// Macro for defining a command
/// Args are: cmd_name the name of the struct for the command
/// name: the string name of the command
/// about: an about string describing the command
/// extra_args: a closure taking an App that addes any additional argument stuff and returns an App
/// is_expr: a closure taking a string arg that checks if the passed string is one that should call this command
/// cmd_expr: a closure taking matches and env that runs to execute the command
macro_rules! command {
    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $is_expr:expr, $cmd_expr:expr) => {
        pub struct $cmd_name {
            clap: RefCell<App<'static, 'static>>,
        }

        impl $cmd_name {
            pub fn new() -> $cmd_name {
                let clap = start_clap($name, $about);
                let extra = $extra_args(clap);
                $cmd_name {
                    clap: RefCell::new(extra),
                }
            }
        }

        impl Cmd for $cmd_name {
            fn exec(&self, env:&mut Env, args:&mut Iterator<Item=&str>) -> bool {
                exec_match(&self.clap, env, args, $cmd_expr)
            }

            fn is(&self, l: &str) -> bool {
                $is_expr(l)
            }

            fn get_name(&self) -> &'static str {
                $name
            }

            fn print_help(&self) {
                if let Err(res) = self.clap.borrow_mut().print_help() {
                    println!("Couldn't print help: {}", res);
                }
            }
        }
    }
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
    let mut max_len = 4;
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

command!(Quit,
         "quit",
         "Quit click",
         |clap| {clap},
         |l| {l == "q" || l == "quit"},
         |_,env| {env.quit = true;}
);

command!(Context,
         "context",
         "Set the current context (will clear any selected pod)",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("context")
                      .help("The name of the context")
                      .required(true)
                      .index(1))
         },
         |l| {l == "ctx" || l == "context"},
         |matches, env| {
             let context = matches.value_of("context");
             env.set_context(context);
             // TODO: Clear current pod
         }
);


command!(Namespace,
         "namespace",
         "Set the current namespace",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("namespace")
                      .help("The namespace to use")
                      .required(true)
                      .index(1))
         },
         |l| {l == "ns" || l == "namespace"},
         |matches, env| {
             let ns = matches.value_of("namespace");
             env.set_namespace(ns);
         }
);

command!(Pods,
         "pods",
         "Get pods in the current context",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("label")
                      .short("l")
                      .long("label")
                      .help("Get pods with specified label selector (example: app=kinesis2prom)")
                      .takes_value(true))
                 .arg(Arg::with_name("regex")
                      .short("r")
                      .long("regex")
                      .help("Filter pods by the specified regex")
                      .takes_value(true))
         },
         |l| { l == "pods" },
         |matches, env| {
             let mut urlstr = if let Some(ref ns) = env.namespace {
                 format!("/api/v1/namespaces/{}/pods", ns)
             } else {
                 "/api/v1/pods".to_owned()
             };

             if let Some(label_selector) = matches.value_of("label") {
                 urlstr.push_str("?labelSelector=");
                 urlstr.push_str(label_selector);
             }

             let pl: Option<PodList> = env.run_on_kluster(|k| {
                 k.get(urlstr.as_str()).unwrap()
             });
             if let Some(l) = pl {
                 if let Some(pattern) = matches.value_of("regex") {
                     if let Ok(regex) = Regex::new(pattern) {
                         let filtered = l.items.into_iter().filter(|x| regex.is_match(x.metadata.name.as_str())).collect();
                         let new_podlist = PodList {
                             items: filtered
                         };
                         print_podlist(&new_podlist);
                         env.set_podlist(Some(new_podlist));
                     } else {
                         println!("Invalid regex: {}", pattern);
                     }
                 }
                 else {
                     print_podlist(&l);
                     env.set_podlist(Some(l));
                 }
             }
         }
);

command!(Logs,
         "logs",
         "Get logs from a container in the current pod",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("container")
                      .help("Specify which container to get logs from")
                      .required(true)
                      .index(1))
                 .arg(Arg::with_name("follow")
                      .short("f")
                      .long("follow")
                      .help("Follow the logs as new records arrive (stop with ^D)")
                      .takes_value(false))
         },
         |l| { l == "logs" },
         |matches, env| {
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
         }
);

/// Utility function for describe to print out value
fn describe_format_value(v: Value) -> String {
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

command!(Describe,
         "describe",
         "Describe the active pod",
         |clap| {clap},
         |l| { l == "describe" },
         |_matches, env| {
             if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
                 let url = format!("/api/v1/namespaces/{}/pods/{}", ns, pod);
                 let pod_value = env.run_on_kluster(|k| {
                     k.get_value(url.as_str()).unwrap()
                 });
                 println!("{}", describe_format_value(pod_value.unwrap()));
             }}
         }
);

command!(Exec,
         "exec",
         "exec specified command on active pod",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("command")
                      .help("The command to execute")
                      .required(true)
                      .index(1))
         },
         |l| { l == "exec" },
         |matches, env| {
             let cmd = matches.value_of("command").unwrap(); // safe as required
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
         }
);

fn containers_format_value(v: Value) -> String {
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

command!(Containers,
         "containers",
         "List containers on active pod",
         |clap| { clap },
         |l| { l == "conts" || l == "containers" },
         |_matches, env| {
             if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
                 let url = format!("/api/v1/namespaces/{}/pods/{}", ns, pod);
                 let pod_value = env.run_on_kluster(|k| {
                     k.get_value(url.as_str()).unwrap()
                 });
                 println!("{}", containers_format_value(pod_value.unwrap()));
             } else {
                 println!("No active pod");
             }} else {
                 println!("No active namespace");
             }
         }
);


fn format_event(event: &Event) -> String {
    format!("{} - {}\n count: {}\n reason: {}\n",
            event.last_timestamp.with_timezone(&Local),
            event.message,
            event.count,
            event.reason)
}

command!(Events,
         "events",
         "Get events for the active pod",
         |clap| { clap },
         |l| { l == "events" },
         |_matches, env| {
             if let Some(ref ns) = env.namespace { if let Some(ref pod) = env.current_pod {
                 let url = format!("/api/v1/namespaces/{}/events?fieldSelector=involvedObject.name={},involvedObject.namespace={}",
                                   ns,pod,ns);
                 let oel: Option<EventList> = env.run_on_kluster(|k| {
                     k.get(url.as_str()).unwrap()
                 });
                 if let Some(el) = oel {
                     if el.items.len() > 0 {
                         for e in el.items.iter() {
                             println!("{}",format_event(e));
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
         }
);

command!(Nodes,
         "nodes",
         "Get nodes in current namespace",
         |clap| { clap },
         |l| { l == "nodes" },
         |_matches, env| {
             let url = "/api/v1/nodes";
             let nl: Option<NodeList> = env.run_on_kluster(|k| {
                 k.get(url).unwrap()
             });
             if let Some(ref n) = nl {
                 print_nodelist(&n);
             }
         }
);
