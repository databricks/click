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
use kube::{ContainerState, DeploymentList, Event, EventList, Pod, PodList, NodeList, NodeCondition, ServiceList};

use ansi_term::Colour::Green;
use clap::{Arg, ArgMatches, App, AppSettings};
use chrono::DateTime;
use chrono::offset::utc::UTC;
use chrono::offset::local::Local;
use prettytable::{format, Table};
use prettytable::cell::Cell;
use prettytable::row::Row;
use serde_json;
use serde_json::Value;
use regex::Regex;

use std::cell::RefCell;
use std::error::Error;

use std::iter::Iterator;
use std::io::{self, BufRead, BufReader, Write};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Duration;

lazy_static! {
    static ref TBLFMT: format::TableFormat = format::FormatBuilder::new()
        .separators(
            &[format::LinePosition::Title, format::LinePosition::Bottom],
						format::LineSeparator::new('-', '+', '+', '+')
				)
        .padding(1,1)
        .build();
}

pub trait Cmd {
    // break if returns true
    fn exec(&self, &mut Env, &mut Iterator<Item=&str>) -> bool;
    fn is(&self, &str) -> bool;
    fn get_name(&self) -> &'static str;
    fn try_complete(&self, args: Vec<&str>, env: &Env) -> (usize, Vec<String>);
    fn print_help(&self);
    fn about(&self) -> &'static str;
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
///
/// # Args
/// * cmd_name: the name of the struct for the command
/// * name: the string name of the command
/// * about: an about string describing the command
/// * extra_args: a closure taking an App that addes any additional argument stuff and returns an App
/// * is_expr: a closure taking a string arg that checks if the passed string is one that should call this command
/// * cmd_expr: a closure taking matches and env that runs to execute the command
/// * cmplt_expr: an expression to return possible compeltions for the command
///
/// # Example
/// ```
/// # #[macro_use] extern crate click;
/// # fn main() {
/// command!(Quit,
///         "quit",
///         "Quit click",
///         |clap| {clap},
///         |l| {l == "q" || l == "quit"},
///         |_,env| {env.quit = true;}
/// );
/// # }
/// ```
macro_rules! command {
    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $is_expr:expr, $cmplt_expr: expr, $cmd_expr:expr) => {
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
                    print!("Couldn't print help: {}", res);
                }
                println!(); // clap print_help doesn't add final newline
            }

            fn about(&self) -> &'static str {
                $about
            }

            fn try_complete(&self, args: Vec<&str>, env: &Env) -> (usize, Vec<String>) {
                $cmplt_expr(args, env)
            }
        }
    }
}

/// Just return what we're given.  Useful for no-op closures in
/// command! macro invocation
fn identity<T>(t: T) -> T {
    t
}

/// A completer that does nothing, used for commands that don't do completion
fn noop_complete(_: Vec<&str>, _:&Env) -> (usize, Vec<String>) {
    (0, Vec::new())
}

/// Check if a pod has a waiting container
fn has_waiting(pod: &Pod) -> bool {
    if let Some(ref stats) = pod.status.container_statuses {
        stats.iter().any(|cs| {
            if let ContainerState::Waiting { .. } = cs.state {
                true
            } else {
                false
            }
        })
    } else {
        false
    }
}

// Figure out the right thing to print for the phase of the given pod
fn phase_str(pod: &Pod) -> &str {
    if let Some(_) = pod.metadata.deletion_timestamp {
        // Was deleted
        "Terminating"
    } else if has_waiting(pod) {
        "ContainerCreating"
    } else {
        pod.status.phase.as_str()
    }
}

fn phase_style(phase: &str) -> &str {
    match phase {
        "Pending" | "Running" => "Fg",
        "Terminated" => "Fr",
        "ContainerCreating" => "Fy",
        "Succeeded" => "Fb",
        "Failed" => "Fr",
        "Unknown" => "Fr",
        _ => "Fr",
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

/// if s is longer than max_len it will be shorted and have ... added to be max_len
fn shorten_to(s: String, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[0..(max_len-3)])
    } else {
        s
    }
}

/// Print out the specified list of pods in a pretty format
fn print_podlist(podlist: &PodList, show_labels: bool, show_annot: bool, show_namespace: bool) {
    let mut table = Table::new();
    let mut title_row = row!["####", "Name", "Phase", "Age", "Restarts"];
    if show_labels {
        title_row.add_cell(Cell::new("Labels"));
    }
    if show_annot {
        title_row.add_cell(Cell::new("Annotations"));
    }
    if show_namespace {
        title_row.add_cell(Cell::new("Namespace"));
    }
    table.set_titles(title_row);

    for (i,pod) in podlist.items.iter().enumerate() {
        let mut row = Vec::new();
        row.push(Cell::new_align(format!("{}",i).as_str(), format::Alignment::RIGHT));
        row.push(Cell::new(pod.metadata.name.as_str()));
        let ps = phase_str(pod);
        row.push(Cell::new(ps).style_spec(phase_style(ps)));
        if let Some(ts) = pod.metadata.creation_timestamp {
            row.push(Cell::new(time_since(ts).as_str()));
        } else {
            row.push(Cell::new("unknown"));
        }

        let restarts = if let Some(ref stats) = pod.status.container_statuses {
            stats.iter().fold(0, |acc, ref x| acc + x.restart_count)
        } else {
            0
        };
        row.push(Cell::new(format!("{}", restarts).as_str()));

        if show_labels {
            row.push(Cell::new(keyval_string(&pod.metadata.labels).as_str()));
        }

        if show_annot {
            row.push(Cell::new(keyval_string(&pod.metadata.annotations).as_str()));
        }

        if show_namespace {
            row.push(Cell::new(pod.metadata.namespace.as_ref().unwrap_or(&"[Unknown]".to_owned())));
        }
        table.add_row(Row::new(row));
    }
    table.set_format(TBLFMT.clone());
    table.printstd();
}

/// Build a multi-line string of the specified keyvals
fn keyval_string(keyvals: &Option<serde_json::Map<String, Value>>) -> String {
    let mut buf = String::new();
    if let &Some(ref lbs) = keyvals {
        for (key,val) in lbs.iter() {
            buf.push_str(key);
            buf.push('=');
            if let Some(s) = val.as_str() {
                buf.push_str(s);
            } else {
                buf.push_str(format!("{}", val).as_str());
            }
            buf.push('\n');
        }
    }
    buf
}

/// Print out the specified list of nodes in a pretty format
fn print_nodelist(nodelist: &NodeList, labels: bool) {
    let mut table = Table::new();
    let mut title_row = row!["####", "Name", "State", "Age"];
    if labels {
        title_row.add_cell(Cell::new("Labels"));
    }
    table.set_titles(title_row);
    for (i, node) in nodelist.items.iter().enumerate() {
        let readycond: Vec<&NodeCondition> = node.status.conditions.iter().filter(|c| c.typ == "Ready").collect();
        let (state, state_style) =
            if let Some(cond) = readycond.get(0) {
                if cond.status == "True" {
                    ("Ready", "Fg")
                } else {
                    ("Not Ready", "Fr")
                }
            } else {
                ("Unknown", "Fy")
            };

        let state =
            if let Some(b) = node.spec.unschedulable {
                if b {
                    format!("{}\nSchedulingDisabled", state)
                } else {
                    state.to_owned()
                }
            } else {
                state.to_owned()
            };

        let mut row = Vec::new();
        row.push(Cell::new_align(format!("{}",i).as_str(), format::Alignment::RIGHT));
        row.push(Cell::new(node.metadata.name.as_str()));
        row.push(Cell::new(state.as_str()).style_spec(state_style));
        row.push(Cell::new(format!("{}", time_since(node.metadata.creation_timestamp.unwrap())).as_str()));
        if labels {
            row.push(Cell::new(keyval_string(&node.metadata.labels).as_str()));
        }
        table.add_row(Row::new(row));
    }
    table.set_format(TBLFMT.clone());
    table.printstd();
}

/// Print out the specified list of deployments in a pretty format
fn print_deployments(deplist: &DeploymentList) {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "Desired", "Current", "Up To Date", "Available", "Age"]);
    for (i, dep) in deplist.items.iter().enumerate() {
        let mut row = Vec::new();
        row.push(Cell::new_align(format!("{}",i).as_str(), format::Alignment::RIGHT));
        row.push(Cell::new(dep.metadata.name.as_str()));
        row.push(Cell::new_align(format!("{}", dep.spec.replicas).as_str(), format::Alignment::CENTER));
        row.push(Cell::new_align(format!("{}", dep.status.replicas).as_str(), format::Alignment::CENTER));
        row.push(Cell::new_align(format!("{}", dep.status.updated).as_str(), format::Alignment::CENTER));
        row.push(Cell::new_align(format!("{}", dep.status.available).as_str(), format::Alignment::CENTER));
        row.push(Cell::new(format!("{}", time_since(dep.metadata.creation_timestamp.unwrap())).as_str()));
        table.add_row(Row::new(row));
    }
    table.set_format(TBLFMT.clone());
    table.printstd();
}

/// Print out the specified list of deployments in a pretty format
fn print_servicelist(servlist: &ServiceList, _show_labels: bool) {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "ClusterIP", "External IPs", "Port(s)", "Age"]);
    for (i, service) in servlist.items.iter().enumerate() {
        let mut row = Vec::new();
        row.push(Cell::new_align(format!("{}",i).as_str(), format::Alignment::RIGHT));
        row.push(Cell::new(service.metadata.name.as_str()));
        row.push(Cell::new(format!("{}", service.spec.cluster_ip.as_ref().unwrap_or(&"<none>".to_owned())).as_str()));
        if let Some(ref eips) = service.spec.external_ips {
            row.push(Cell::new(shorten_to(eips.join(", "), 18).as_str()));
        } else {
            // look in the status for the elb name
            if let Some(ing_val) = service.status.pointer("/loadBalancer/ingress") {
                if let Some(ing_arry) = ing_val.as_array() {
                    let strs: Vec<&str> = ing_arry.iter().map(|v| {
                        if let Some(hv) = v.get("hostname") {
                            hv.as_str().unwrap_or("")
                        } else {
                            ""
                        }
                    }).collect();
                    let s = strs.join(", ");
                    row.push(Cell::new(shorten_to(s,18).as_str()));
                } else {
                    row.push(Cell::new("<none>"));
                }
            } else {
                row.push(Cell::new("<none>"));
            }
        }
        let port_strs: Vec<String> =
            if let Some(ref ports) = service.spec.ports {
                ports.iter().map(|p| {
                    if let Some(np) = p.node_port {
                        format!("{}:{}/{}", p.port, np, p.protocol)
                    } else {
                        format!("{}/{}", p.port, p.protocol)
                    }
                }).collect()
            } else {
                vec!["<none>".to_owned()]
            };
        row.push(Cell::new(port_strs.join(",").as_str()));
        row.push(Cell::new(format!("{}", time_since(service.metadata.creation_timestamp.unwrap())).as_str()));
        table.add_row(Row::new(row));
    }
    table.set_format(TBLFMT.clone());
    table.printstd();
}


fn val_to_str<'a>(v: &'a Value, key: &str) -> &'a str {
    if let Some(v) = v.get(key) {
        v.as_str().unwrap_or("unknown")
    } else {
        "unknown"
    }
}

// Command defintions below.  See documentation for the command! macro for an explanation of arguments passed here

command!(Quit,
         "quit",
         "Quit click",
         identity,
         |l| {l == "q" || l == "quit"},
         noop_complete,
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
         |args: Vec<&str>, env: &Env| {
             if args.len() == 0 {
                 // full command, but no args yet, so suggest everything
                 let mut v = Vec::new();
                 for context in env.config.contexts.keys() {
                     v.push(context.clone());
                 }
                 (0, v)
             }
             else if args.len() == 1 {
                 // we only take one arg
                 let mut v = Vec::new();
                 let line = args.get(0).unwrap(); // we just checked
                 for context in env.config.contexts.keys() {
                     if context.starts_with(line) {
                         v.push(context.clone());
                     }
                 }
                 (line.len(), v)
             } else {
                 (0, Vec::new())
             }
         },
         |matches, env| {
             let context = matches.value_of("context");
             if let (&Some(ref k), Some(c)) = (&env.kluster, context) {
                 if k.name == c { // no-op if we're already in the specified context
                     return;
                 }
             }
             env.set_context(context);
             env.clear_current();
         }
);

command!(Clear,
         "clear",
         "Clear the currently selected kubernetes object",
         identity,
         |l| { l == "clear" },
         noop_complete,
         |_, env| {
             env.clear_current();
         }
);

command!(Namespace,
         "namespace",
         "Set the current namespace (no arg for no namespace)",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("namespace")
                      .help("The namespace to use")
                      .required(false)
                      .index(1))
         },
         |l| {l == "ns" || l == "namespace"},
         noop_complete,
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
                 .arg(Arg::with_name("showlabels")
                      .short("L")
                      .long("show-labels")
                      .help("Show pod labels as column in output")
                      .takes_value(false))
                 .arg(Arg::with_name("showannot")
                      .short("A")
                      .long("show-annotations")
                      .help("Show pod annotations as column in output")
                      .takes_value(false))
         },
         |l| { l == "pods" },
         noop_complete,
         |matches, env| {
             let mut urlstr = if let Some(ref ns) = env.namespace {
                 format!("/api/v1/namespaces/{}/pods", ns)
             } else {
                 "/api/v1/pods".to_owned()
             };

             let mut pushed_label = false;
             if let Some(label_selector) = matches.value_of("label") {
                 urlstr.push_str("?labelSelector=");
                 urlstr.push_str(label_selector);
                 pushed_label = true;
             }

             if let ::KObj::Node(ref node) = env.current_object {
                 if pushed_label {
                     urlstr.push('&');
                 } else {
                     urlstr.push('?');
                 }
                 urlstr.push_str("fieldSelector=spec.nodeName=");
                 urlstr.push_str(node);
             }

             let pl: Option<PodList> = env.run_on_kluster(|k| {
                 k.get(urlstr.as_str())
             });

             if let Some(l) = pl {
                 let final_list =
                     if let Some(pattern) = matches.value_of("regex") {
                         if let Ok(regex) = Regex::new(pattern) {
                             let filtered = l.items.into_iter().filter(|x| regex.is_match(x.metadata.name.as_str())).collect();
                             Some(PodList {
                                 items: filtered
                             })
                         } else {
                             println!("Invalid regex: {}", pattern);
                             None
                         }
                     } else {
                         Some(l)
                     };
                 if let Some(ref l) = final_list {
                     print_podlist(l, matches.is_present("showlabels"), matches.is_present("showannot"), env.namespace.is_none());
                 }
                 env.set_podlist(final_list);
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
         noop_complete,
         |matches, env| {
             let cont = matches.value_of("container").unwrap(); // required so unwrap safe
             let follow = matches.is_present("follow");
             if let Some(ref ns) = env.current_object_namespace { if let Some(ref pod) = env.current_pod() {
                 let mut url = format!("/api/v1/namespaces/{}/pods/{}/log?container={}", ns, pod, cont);
                 if follow {
                     url.push_str("&follow=true");
                 }
                 let logs_reader = env.run_on_kluster(|k| {
                     k.get_read(url.as_str(), Some(Duration::new(1, 0)))
                 });
                 if let Some(lreader) = logs_reader {
                     let mut reader = BufReader::new(lreader);
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
                 }
             }}
         }
);


/// get key/vals out of metadata
fn get_keyval_str(v: &Value, parent: &str, title: &str) -> String {
    let mut outstr = title.to_owned();
    if let Some(keyvals) = v.get(parent).unwrap().as_object() {
        let mut first = true;
        for key in keyvals.keys() {
            if !first {
                outstr.push('\n');
                outstr.push('\t');
            }
            first = false;
            outstr.push('\t');
            outstr.push_str(key);
            outstr.push('=');
            outstr.push_str(keyvals.get(key).unwrap().as_str().unwrap());
        }
    }
    outstr
}


/// Get volume info out of volume array
fn get_volume_str(v: &Value) -> String {
    let mut buf = String::new();
    buf.push_str("Volumes:\n");
    if let Some(vol_arry) = v.as_array() {
        for vol in vol_arry.iter() {
            buf.push_str(format!("  Name: {}\n", val_to_str(vol, "name")).as_str());
            if vol.get("emptyDir").is_some() {
                buf.push_str("    Type:\tEmptyDir (a temporary directory that shares a pod's lifetime)\n")
            }
            if let Some(conf_map) = vol.get("configMap") {
                buf.push_str("    Type:\tConfigMap (a volume populated by a ConfigMap)\n");
                buf.push_str(format!("    Name:\t{}\n", val_to_str(conf_map, "name")).as_str());
            }
            if let Some(secret) = vol.get("secret") {
                buf.push_str("    Type:\tSecret (a volume populated by a Secret)\n");
                buf.push_str(format!("    SecretName:\t{}\n", val_to_str(secret, "secretName")).as_str());
            }
            if let Some(aws) = vol.get("awsElasticBlockStore") {
                buf.push_str("    Type:\tAWS Block Store (An AWS Disk resource exposed to the pod)\n");
                buf.push_str(format!("    VolumeId:\t{}\n", val_to_str(aws, "volumeID")).as_str());
                buf.push_str(format!("    FSType:\t{}\n", val_to_str(aws, "fsType")).as_str());
                let mut pnum = 0;
                if let Some(part) = aws.get("partition") {
                    if let Some(p) = part.as_u64() {
                        pnum = p;
                    }
                }
                buf.push_str(format!("    Partition#:\t{}\n", pnum).as_str());
                if let Some(read_only) = aws.get("readOnly") {
                    if read_only.as_bool().unwrap() {
                        buf.push_str("    Read-Only:\tTrue\n");
                    }
                    else {
                        buf.push_str("    Read-Only:\tFalse\n");
                    }
                } else {
                    buf.push_str("    Read-Only:\tFalse\n");
                }
            }
        }
    }
    buf
}

/// Utility function for describe to print out value
fn describe_format_pod(v: Value) -> String {
    let metadata = v.get("metadata").unwrap();
    let spec = v.get("spec").unwrap();
    let status = v.get("status").unwrap();
    let created: DateTime<UTC> = DateTime::from_str(val_to_str(metadata, "creationTimestamp")).unwrap();

    let volumes = spec.get("volumes");
    let volstr =
        if let Some(vols) = volumes {
            get_volume_str(vols)
        } else {
            "No Volumes".to_owned()
        };

    format!("Name:\t\t{}\n\
Namespace:\t{}
Node:\t\t{}
IP:\t\t{}
Created at:\t{} ({})
Status:\t\t{}
{}
{}
{}", // TODO: Controllers
            val_to_str(metadata, "name"),
            val_to_str(metadata, "namespace"),
            val_to_str(spec, "nodeName"),
            val_to_str(status, "podIP"),
            created, created.with_timezone(&Local),
            Green.paint(val_to_str(status, "phase")),
            get_keyval_str(metadata, "labels", "Labels:\t"),
            get_keyval_str(metadata, "annotations", "Annotations:"),
            volstr,
    )
}

/// Utility function for describe to print out value
fn describe_format_node(v: Value) -> String {
    let metadata = v.get("metadata").unwrap();
    let spec = v.get("spec").unwrap();
    let created: DateTime<UTC> = DateTime::from_str(val_to_str(metadata, "creationTimestamp")).unwrap();

    format!("Name:\t\t{}
{}
Created at:\t{} ({})
ProviderId:\t{}",
            val_to_str(metadata, "name"),
            get_keyval_str(metadata, "labels", "Labels"),
            created, created.with_timezone(&Local),
            val_to_str(spec, "providerID"),
    )
}

command!(Describe,
         "describe",
         "Describe the active pod",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("json")
                      .short("j")
                      .long("json")
                      .help("output full json")
                      .takes_value(false))
         },
         |l| { l == "describe" },
         noop_complete,
         |matches, env| {
             match env.current_object {
                 ::KObj::None => println!("No active object to describe"),
                 ::KObj::Pod(ref pod) => {
                     if let Some(ref ns) = env.current_object_namespace {
                         // describe the active pod
                         let url = format!("/api/v1/namespaces/{}/pods/{}", ns, pod);
                         let pod_value = env.run_on_kluster(|k| {
                             k.get_value(url.as_str())
                         });
                         if let Some(pval) = pod_value {
                             if matches.is_present("json") {
                                 println!("{}", serde_json::to_string_pretty(&pval).unwrap());
                             } else {
                                 println!("{}", describe_format_pod(pval));
                             }
                         }
                     } else {
                         println!("Don't know namespace for {}", pod);
                     }
                 },
                 ::KObj::Node(ref node) => {
                     // describe the active node
                     let url = format!("/api/v1/nodes/{}", node);
                     let node_value = env.run_on_kluster(|k| {
                         k.get_value(url.as_str())
                     });
                     if let Some(nval) = node_value {
                         if matches.is_present("json") {
                             println!("{}", serde_json::to_string_pretty(&nval).unwrap());
                         } else {
                             println!("{}", describe_format_node(nval));
                         }
                     }
                 },
                 ::KObj::Deployment(ref deployment) => {
                     if let Some(ref ns) = env.current_object_namespace {
                         let url = format!("/apis/extensions/v1beta1/namespaces/{}/deployments/{}", ns, deployment);
                         let dep_value = env.run_on_kluster(|k| {
                             k.get_value(url.as_str())
                         });
                         if let Some(dval) = dep_value {
                             if matches.is_present("json") {
                                 println!("{}", serde_json::to_string_pretty(&dval).unwrap());
                             } else {
                                 println!("Deployment not supported without -j yet");
                             }
                         }
                     }
                 },
                 ::KObj::Service(ref service) => {
                     if let Some(ref ns) = env.current_object_namespace {
                         let url = format!("/api/v1/namespaces/{}/services/{}", ns, service);
                         let service_value = env.run_on_kluster(|k| {
                             k.get_value(url.as_str())
                         });
                         if let Some(sval) = service_value {
                             if matches.is_present("json") {
                                 println!("{}", serde_json::to_string_pretty(&sval).unwrap());
                             } else {
                                 println!("Service not supported without -j yet");
                             }
                         }
                     }
                 },
             }
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
                 .arg(Arg::with_name("container")
                      .short("c")
                      .long("container")
                      .help("Exec in the specified container")
                      .takes_value(true))
         },
         |l| { l == "exec" },
         noop_complete,
         |matches, env| {
             let cmd = matches.value_of("command").unwrap(); // safe as required
             if let (Some(ref kluster), Some(ref ns), Some(ref pod)) = (env.kluster.as_ref(), env.current_object_namespace.as_ref(), env.current_pod().as_ref()) {
                 let contargs =
                     if let Some(container) = matches.value_of("container") {
                         vec!("-c", container)
                     } else {
                         vec!()
                     };
                 let status = Command::new("kubectl")
                     .arg("--namespace")
                     .arg(ns)
                     .arg("--context")
                     .arg(&kluster.name)
                     .arg("exec")
                     .arg("-it")
                     .arg(pod)
                     .args(contargs.iter())
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

command!(Delete,
         "delete",
         "Delete the active object (will ask for confirmation)",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("grace")
                      .short("g")
                      .long("gracePeriod")
                      .help("The duration in seconds before the object should be deleted.")
                      .validator(|s: String| {
                          s.parse::<u32>().map(|_| ()).map_err(|e| e.description().to_owned())
                      })
                      .takes_value(true))
                 .arg(Arg::with_name("orphan")
                      .short("o")
                      .long("orphan")
                      .help("If specified, dependent objects are orphaned.")
                      .takes_value(false))
         },
         |l| { l == "delete" },
         noop_complete,
         |matches, env| {
             if let Some(ref ns) = env.current_object_namespace {
                 if let Some(mut url) = match env.current_object {
                     ::KObj::Pod(ref pod) => {
                         print!("Delete pod {} [y/N]? ", pod);
                         Some(format!("/api/v1/namespaces/{}/pods/{}", ns, pod))
                     },
                     ::KObj::Deployment(ref dep) => {
                         print!("Delete deployment {} [y/N]? ", dep);
                         Some(format!("/apis/extensions/v1beta1/namespaces/{}/deployments/{}", ns, dep))
                     },
                     ::KObj::None => {
                         println!("No active object");
                         None
                     },
                     _ => {
                         println!("Can only delete pods or deployments");
                         None
                     },
                 } {
                     io::stdout().flush().ok().expect("Could not flush stdout");
                     let mut conf = String::new();
                     if let Ok(_) = io::stdin().read_line(&mut conf) {
                         if conf.trim() == "y" || conf.trim() == "yes" {
                             if let Some(grace) = matches.value_of("grace") {
                                 // already validated that it's a legit number
                                 url.push_str("&gracePeriodSeconds=");
                                 url.push_str(grace);
                             }
                             if matches.is_present("orphan") {
                                 if matches.is_present("grace") {
                                     url.push('&');
                                 }
                                 url.push_str("orphanDependents=true");
                             }
                             let result = env.run_on_kluster(|k| {
                                 k.delete(url.as_str())
                             });
                             if let Some(_) = result {
                                 println!("Deleted");
                             } else {
                                 println!("Failed to delete");
                             }
                         } else {
                             println!("Not deleting");
                         }
                     } else {
                         println!("Could not read response, not deleting.");
                     }
                 }
             } else {
                 println!("No active namespace"); // TODO: Can you delete without a namespace?
             }
         }
);

fn containers_string(pod: &Pod) -> String {
    let mut buf = String::new();
    if let Some(ref stats) = pod.status.container_statuses {
        for cont in stats.iter() {
            buf.push_str(format!("Name:\t{}\n", cont.name).as_str());
            buf.push_str(format!("  Image:\t{}\n", cont.image).as_str());
            buf.push_str(format!("  State:\t{}\n", cont.state).as_str());

            // find the spec for this container
            let mut spec_it = pod.spec.containers.iter().filter(|cs| {
                cs.name == cont.name
            });
            if let Some(spec) = spec_it.next() {
                if let Some(ref vols) = spec.volume_mounts {
                    buf.push_str("  Volumes:\n");
                    for vol in vols.iter() {
                        buf.push_str(format!("   {}\n", vol.name).as_str());
                        buf.push_str(format!("    Path:\t{}\n", vol.mount_path).as_str());
                        buf.push_str(format!("    Sub-Path:\t{}\n", vol.sub_path.as_ref().unwrap_or(&"".to_owned())).as_str());
                        buf.push_str(format!("    Read-Only:\t{}\n", vol.read_only.unwrap_or(false)).as_str());
                    }
                } else {
                    buf.push_str("  No Volumes\n");
                }
            }
            buf.push('\n');
        }
    } else {
        buf.push_str("<No Containers>\n");
    }
    buf
}

command!(Containers,
         "containers",
         "List containers on active pod",
         identity,
         |l| { l == "conts" || l == "containers" },
         noop_complete,
         |_matches, env| {
             if let Some(ref ns) = env.current_object_namespace { if let Some(ref pod) = env.current_pod() {
                 let url = format!("/api/v1/namespaces/{}/pods/{}", ns, pod);
                 let pod_opt: Option<Pod> = env.run_on_kluster(|k| {
                     k.get(url.as_str())
                 });
                 if let Some(pod) = pod_opt {
                     print!("{}", containers_string(&pod)); // extra newline in returned string
                 }
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
         identity,
         |l| { l == "events" },
         noop_complete,
         |_matches, env| {
             if let Some(ref ns) = env.current_object_namespace { if let Some(ref pod) = env.current_pod() {
                 let url = format!("/api/v1/namespaces/{}/events?fieldSelector=involvedObject.name={},involvedObject.namespace={}",
                                   ns,pod,ns);
                 let oel: Option<EventList> = env.run_on_kluster(|k| {
                     k.get(url.as_str())
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
         "Get nodes in current context",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("labels")
                      .short("l")
                      .long("labels")
                      .help("include labels in output")
                      .takes_value(false))
         },
         |l| { l == "nodes" },
         noop_complete,
         |matches, env| {
             let url = "/api/v1/nodes";
             let nl: Option<NodeList> = env.run_on_kluster(|k| {
                 k.get(url)
             });
             if let Some(ref n) = nl {
                 print_nodelist(&n, matches.is_present("labels"));
             }
             env.set_nodelist(nl);
         }
);

command!(Services,
         "services",
         "Get services in current context and namespace (if set)",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("labels")
                      .short("l")
                      .long("labels")
                      .help("include labels in output")
                      .takes_value(false))
         },
         |l| { l == "services" },
         noop_complete,
         |matches, env| {
             let url =
                 if let Some(ref ns) = env.namespace {
                     format!("/api/v1/namespaces/{}/services", ns)
                 } else {
                     "/api/v1/services".to_owned()
                 };
             let sl: Option<ServiceList> = env.run_on_kluster(|k| {
                 k.get(url.as_str())
             });
             if let Some(ref s) = sl {
                 print_servicelist(&s, matches.is_present("labels"));
             } else {
                 println!("no services");
             }
             env.set_servicelist(sl);
         }
);


command!(EnvCmd,
         "env",
         "Print info about the current environment",
         identity,
         |l| { l == "env" },
         noop_complete,
         |_matches, env| {
             println!("{}", env);
         }
);

command!(Deployments,
         "deployments",
         "Get deployments (in current namespace if there is one)",
         |clap: App<'static, 'static>| {
             clap.arg(Arg::with_name("label")
                      .short("l")
                      .long("label")
                      .help("Get deployments with specified label selector")
                      .takes_value(true))
                 .arg(Arg::with_name("regex")
                      .short("r")
                      .long("regex")
                      .help("Filter deployments by the specified regex")
                      .takes_value(true))
         },
         |l| { l == "deps" || l == "deployments" },
         noop_complete,
         |matches, env| {
             let mut urlstr = if let Some(ref ns) = env.namespace {
                 format!("/apis/extensions/v1beta1/namespaces/{}/deployments", ns)
             } else {
                 "/apis/extensions/v1beta1/deployments".to_owned()
             };

             if let Some(label_selector) = matches.value_of("label") {
                 urlstr.push_str("?labelSelector=");
                 urlstr.push_str(label_selector);
             }

             let dl: Option<DeploymentList> = env.run_on_kluster(|k| {
                 k.get(urlstr.as_str())
             });

             if let Some(ref d) = dl {
                 print_deployments(&d);
             }
             env.set_deplist(dl);
         }
);

command!(UtcCmd,
         "utc",
         "Print current time in UTC",
         identity,
         |l| { l == "utc" },
         noop_complete,
         |_, _| {
             println!("{}", UTC::now());
         }
);
