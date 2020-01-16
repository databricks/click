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

use completer;
use config;
use env::{self, Env, LastList, ObjectSelection};
use kobj::{KObj, ObjType};
use kube::{
    ConfigMapList, ContainerState, Deployment, DeploymentList, Event, EventList, JobList, Metadata,
    NamespaceList, Node, NodeCondition, NodeList, Pod, PodList, ReplicaSetList, SecretList,
    Service, ServiceList, StatefulSetList,
};
use output::ClickWriter;
use table::{opt_sort, CellSpec};
use values::{get_val_as, val_item_count, val_str, val_u64};

use ansi_term::Colour::Yellow;
use chrono::offset::Local;
use chrono::offset::Utc;
use chrono::DateTime;
use clap::{App, AppSettings, Arg, ArgMatches};
use duct;
use humantime::parse_duration;
use prettytable::Cell;
use prettytable::Row;
use prettytable::{format, Table};
use regex::Regex;
use rustyline::completion::Pair as RustlinePair;
use serde_json;
use serde_json::Value;

use std;
use std::cell::RefCell;
use std::cmp;
use std::error::Error;
use std::io::{self, stderr, BufRead, BufReader, Read, Write};
use std::iter::Iterator;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

lazy_static! {
    static ref TBLFMT: format::TableFormat = format::FormatBuilder::new()
        .separators(
            &[format::LinePosition::Title, format::LinePosition::Bottom],
            format::LineSeparator::new('-', '+', '+', '+')
        )
        .padding(1, 1)
        .build();
}

pub trait Cmd {
    // break if returns true
    fn exec(&self, &mut Env, &mut dyn Iterator<Item = &str>, &mut ClickWriter) -> bool;
    fn is(&self, &str) -> bool;
    fn get_name(&self) -> &'static str;
    fn try_complete(&self, index: usize, prefix: &str, env: &Env) -> Vec<RustlinePair>;
    fn complete_option(&self, prefix: &str) -> Vec<RustlinePair>;
    fn write_help(&self, writer: &mut ClickWriter);
    fn about(&self) -> &'static str;
}

/// Get the start of a clap object
fn start_clap(
    name: &'static str,
    about: &'static str,
    aliases: &'static str,
) -> App<'static, 'static> {
    App::new(name)
        .about(about)
        .before_help(aliases)
        .setting(AppSettings::NoBinaryName)
        .setting(AppSettings::DisableVersion)
        .setting(AppSettings::ColoredHelp)
}

/// Run specified closure with the given matches, or print error.  Return true if execed,
/// false on err
fn exec_match<F>(
    clap: &RefCell<App<'static, 'static>>,
    env: &mut Env,
    args: &mut dyn Iterator<Item = &str>,
    writer: &mut ClickWriter,
    func: F,
) -> bool
where
    F: FnOnce(ArgMatches, &mut Env, &mut ClickWriter) -> (),
{
    // TODO: Should be able to not clone and use get_matches_from_safe_borrow, but
    // that causes weird errors involving conflicting arguments being used
    // between invocations of commands
    match clap.borrow_mut().clone().get_matches_from_safe(args) {
        Ok(matches) => {
            func(matches, env, writer);
            true
        }
        Err(err) => {
            clickwrite!(writer, "{}\n", err.message);
            false
        }
    }
}

macro_rules! noop_complete {
    () => {
        vec![]
    };
}

/// Macro for defining a command
///
/// # Args
/// * cmd_name: the name of the struct for the command
/// * name: the string name of the command
/// * about: an about string describing the command
/// * extra_args: closure taking an App that addes any additional argument stuff and returns an App
/// * aliases: a vector of strs that specify what a user can type to invoke this command
/// * cmplt_expr: an expression to return possible completions for the command
/// * cmd_expr: a closure taking matches, env, and writer that runs to execute the command
///
/// # Example
/// ```
/// # #[macro_use] extern crate click;
/// # fn main() {
/// command!(Quit,
///         "quit",
///         "Quit click",
///         identity,
///         vec!["q", "quit", "exit"],
///         noop_complete!(),
///         |matches, env, writer| {env.quit = true;}
/// );
/// # }
/// ```
macro_rules! command {
    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $aliases:expr, $cmplters: expr,
     $cmd_expr:expr) => {
        pub struct $cmd_name {
            aliases: Vec<&'static str>,
            clap: RefCell<App<'static, 'static>>,
            completers: Vec<&'static dyn Fn(&str, &Env) -> Vec<RustlinePair>>,
        }

        impl $cmd_name {
            pub fn new() -> $cmd_name {
                lazy_static! {
                    static ref ALIASES_STR: String =
                        format!("{}:\n    {:?}", Yellow.paint("ALIASES"), $aliases);
                }
                let clap = start_clap($name, $about, &ALIASES_STR);
                let extra = $extra_args(clap);
                $cmd_name {
                    aliases: $aliases,
                    clap: RefCell::new(extra),
                    completers: $cmplters,
                }
            }
        }

        impl Cmd for $cmd_name {
            fn exec(
                &self,
                env: &mut Env,
                args: &mut dyn Iterator<Item = &str>,
                writer: &mut ClickWriter,
            ) -> bool {
                exec_match(&self.clap, env, args, writer, $cmd_expr)
            }

            fn is(&self, l: &str) -> bool {
                self.aliases.contains(&l)
            }

            fn get_name(&self) -> &'static str {
                $name
            }

            fn write_help(&self, writer: &mut ClickWriter) {
                if let Err(res) = self.clap.borrow_mut().write_help(writer) {
                    clickwrite!(writer, "Couldn't print help: {}", res);
                }
                println!(); // clap print_help doesn't add final newline
                            // clap write_help doesn't add final newline
                clickwrite!(writer, "\n");
            }

            fn about(&self) -> &'static str {
                $about
            }

            fn try_complete(&self, index: usize, prefix: &str, env: &Env) -> Vec<RustlinePair> {
                match self.completers.get(index) {
                    Some(completer) => completer(prefix, env),
                    None => vec![],
                }
            }

            /**
             *  Completes all possible long options for this command, with the given prefix.
             *  This is rather gross as we have to do everything inside this method.
             *  clap::arg is private, so we can't define methods that take the traits
             *  that all args implement, and have to handle each individually
             */
            fn complete_option(&self, prefix: &str) -> Vec<RustlinePair> {
                let repoff = prefix.len();
                let parser = &self.clap.borrow().p;

                let flags = parser
                    .flags
                    .iter()
                    .filter(|fb| completer::long_matches(&fb.s.long, prefix))
                    .map(|fb| RustlinePair {
                        display: format!("--{}", fb.s.long.unwrap()),
                        replacement: fb.s.long.unwrap()[repoff..].to_string(),
                    });

                let opts = parser
                    .opts
                    .iter()
                    .filter(|ob| completer::long_matches(&ob.s.long, prefix))
                    .map(|ob| RustlinePair {
                        display: format!("--{}", ob.s.long.unwrap()),
                        replacement: ob.s.long.unwrap()[repoff..].to_string(),
                    });

                flags.chain(opts).collect()
            }
        }
    };
}

/// Just return what we're given.  Useful for no-op closures in
/// command! macro invocation
fn identity<T>(t: T) -> T {
    t
}

/// a clap validator for u32
fn valid_u32(s: String) -> Result<(), String> {
    s.parse::<u32>()
        .map(|_| ())
        .map_err(|e| e.description().to_owned())
}

/// a clap validator for duration
fn valid_duration(s: String) -> Result<(), String> {
    parse_duration(s.as_str())
        .map(|_| ())
        .map_err(|e| e.description().to_owned())
}

/// a clap validator for rfc3339 dates
fn valid_date(s: String) -> Result<(), String> {
    DateTime::parse_from_rfc3339(s.as_str())
        .map(|_| ())
        .map_err(|e| e.description().to_owned())
}

/// a clap validator for boolean
fn valid_bool(s: String) -> Result<(), String> {
    s.parse::<bool>()
        .map(|_| ())
        .map_err(|e| e.description().to_owned())
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
fn phase_str(pod: &Pod) -> String {
    if pod.metadata.deletion_timestamp.is_some() {
        // Was deleted
        "Terminating".to_owned()
    } else if has_waiting(pod) {
        "ContainerCreating".to_owned()
    } else {
        pod.status.phase.clone()
    }
}

// get the number of ready containers and total containers
// or None if that cannot be determined
fn ready_counts(pod: &Pod) -> Option<(u32, u32)> {
    pod.status.container_statuses.as_ref().map(|statuses| {
        let mut count = 0;
        let mut ready = 0;
        for stat in statuses.iter() {
            count += 1;
            if stat.ready {
                ready += 1;
            }
        }
        (ready, count)
    })
}

fn phase_style(phase: &str) -> &'static str {
    phase_style_str(phase)
}

fn phase_style_str(phase: &str) -> &'static str {
    match phase {
        "Pending" | "Running" | "Active" => "Fg",
        "Terminated" | "Terminating" => "Fr",
        "ContainerCreating" => "Fy",
        "Succeeded" => "Fb",
        "Failed" => "Fr",
        "Unknown" => "Fr",
        _ => "Fr",
    }
}

fn time_since(date: DateTime<Utc>) -> String {
    let now = Utc::now();
    let diff = now.signed_duration_since(date);
    if diff.num_days() > 0 {
        format!(
            "{}d {}h",
            diff.num_days(),
            (diff.num_hours() - (24 * diff.num_days()))
        )
    } else if diff.num_hours() > 0 {
        format!(
            "{}h {}m",
            diff.num_hours(),
            (diff.num_minutes() - (60 * diff.num_hours()))
        )
    } else if diff.num_minutes() > 0 {
        format!(
            "{}m {}s",
            diff.num_minutes(),
            (diff.num_seconds() - (60 * diff.num_minutes()))
        )
    } else {
        format!("{}s", diff.num_seconds())
    }
}

/// if s is longer than max_len it will be shorted and have ... added to be max_len
fn shorten_to(s: String, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[0..(max_len - 3)])
    } else {
        s
    }
}

fn create_podlist_specs<'a>(
    pod: Pod,
    show_labels: bool,
    show_annot: bool,
    show_node: bool,
    show_namespace: bool,
) -> (Pod, Vec<CellSpec<'a>>) {
    let mut specs = Vec::new();
    specs.push(CellSpec::new_index());
    specs.push(CellSpec::new_owned(pod.metadata.name.clone()));

    let ready_str = match ready_counts(&pod) {
        Some((ready, count)) => format!("{}/{}", ready, count),
        None => "Unknown".to_owned(),
    };
    specs.push(CellSpec::new_owned(ready_str));

    {
        let ps = phase_str(&pod);
        let ss = phase_style(&ps);
        specs.push(CellSpec::with_style_owned(ps, ss));
    }

    if let Some(ts) = pod.metadata.creation_timestamp {
        specs.push(CellSpec::new_owned(time_since(ts)));
    } else {
        specs.push(CellSpec::new("unknown"));
    }

    let restarts = pod
        .status
        .container_statuses
        .as_ref()
        .map(|stats| stats.iter().fold(0, |acc, ref x| acc + x.restart_count))
        .unwrap_or(0);
    specs.push(CellSpec::new_owned(format!("{}", restarts)));

    if show_labels {
        specs.push(CellSpec::new_owned(keyval_string(&pod.metadata.labels)));
    }

    if show_annot {
        specs.push(CellSpec::new_owned(keyval_string(
            &pod.metadata.annotations,
        )));
    }

    if show_node {
        specs.push(CellSpec::new_owned(match pod.spec.node_name {
            Some(ref nn) => nn.clone(),
            None => "[Unknown]".to_owned(),
        }));
    }

    if show_namespace {
        specs.push(CellSpec::new_owned(match pod.metadata.namespace {
            Some(ref ns) => ns.clone(),
            None => "[Unknown]".to_owned(),
        }));
    }
    (pod, specs)
}

/// Print out the specified list of pods in a pretty format
#[allow(clippy::too_many_arguments)]
fn print_podlist(
    mut podlist: PodList,
    show_labels: bool,
    show_annot: bool,
    show_node: bool,
    show_namespace: bool,
    regex: Option<Regex>,
    sort: Option<&str>,
    reverse: bool,
    writer: &mut ClickWriter,
) -> PodList {
    let mut table = Table::new();
    let mut title_row = row!["####", "Name", "Ready", "Phase", "Age", "Restarts"];

    let show_labels = show_labels
        || sort
            .map(|s| s == "Lables" || s == "labels")
            .unwrap_or(false);
    let show_annot = show_annot
        || sort
            .map(|s| s == "Annotations" || s == "annotations")
            .unwrap_or(false);
    let show_node = show_node || sort.map(|s| s == "Node" || s == "node").unwrap_or(false);
    let show_namespace = show_namespace
        || sort
            .map(|s| s == "Namespace" || s == "namespace")
            .unwrap_or(false);

    if show_labels {
        title_row.add_cell(Cell::new("Labels"));
    }
    if show_annot {
        title_row.add_cell(Cell::new("Annotations"));
    }
    if show_node {
        title_row.add_cell(Cell::new("Node"));
    }
    if show_namespace {
        title_row.add_cell(Cell::new("Namespace"));
    }
    table.set_titles(title_row);

    if let Some(sortcol) = sort {
        match sortcol {
            "Name" | "name" => podlist
                .items
                .sort_by(|p1, p2| p1.metadata.name.partial_cmp(&p2.metadata.name).unwrap()),
            "Ready" | "ready" => podlist.items.sort_by(|p1, p2| {
                opt_sort(ready_counts(p1), ready_counts(p2), |(r1, c1), (r2, c2)| {
                    if c1 < c2 {
                        cmp::Ordering::Less
                    } else if c1 > c2 {
                        cmp::Ordering::Greater
                    } else if r1 < r2 {
                        cmp::Ordering::Less
                    } else if r1 > r2 {
                        cmp::Ordering::Greater
                    } else {
                        cmp::Ordering::Equal
                    }
                })
            }),
            "Age" | "age" => podlist.items.sort_by(|p1, p2| {
                opt_sort(
                    p1.metadata.creation_timestamp,
                    p2.metadata.creation_timestamp,
                    |a1, a2| a1.partial_cmp(a2).unwrap(),
                )
            }),
            "Restarts" | "restarts" => podlist.items.sort_by(|p1, p2| {
                let p1r = p1
                    .status
                    .container_statuses
                    .as_ref()
                    .map(|stats| stats.iter().fold(0, |acc, ref x| acc + x.restart_count))
                    .unwrap_or(0);
                let p2r = p2
                    .status
                    .container_statuses
                    .as_ref()
                    .map(|stats| stats.iter().fold(0, |acc, ref x| acc + x.restart_count))
                    .unwrap_or(0);
                p1r.partial_cmp(&p2r).unwrap()
            }),
            "Labels" | "labels" => podlist.items.sort_by(|p1, p2| {
                let p1s = keyval_string(&p1.metadata.labels);
                let p2s = keyval_string(&p2.metadata.labels);
                p1s.partial_cmp(&p2s).unwrap()
            }),
            "Annotations" | "annotations" => podlist.items.sort_by(|p1, p2| {
                let p1s = keyval_string(&p1.metadata.annotations);
                let p2s = keyval_string(&p2.metadata.annotations);
                p1s.partial_cmp(&p2s).unwrap()
            }),
            "Node" | "node" => podlist.items.sort_by(|p1, p2| {
                opt_sort(
                    p1.spec.node_name.as_ref(),
                    p2.spec.node_name.as_ref(),
                    |p1n, p2n| p1n.partial_cmp(p2n).unwrap(),
                )
            }),
            "Namespace" | "namespace" => podlist.items.sort_by(|p1, p2| {
                opt_sort(
                    p1.metadata.namespace.as_ref(),
                    p2.metadata.namespace.as_ref(),
                    |p1n, p2n| p1n.partial_cmp(p2n).unwrap(),
                )
            }),
            _ => {
                clickwrite!(
                    writer,
                    "Invalid sort col: {}, this is a bug, please report it",
                    sortcol
                );
            }
        }
    }

    let to_map: Box<dyn Iterator<Item = Pod>> = if reverse {
        Box::new(podlist.items.into_iter().rev())
    } else {
        Box::new(podlist.items.into_iter())
    };

    let pods_specs = to_map
        .map(|pod| create_podlist_specs(pod, show_labels, show_annot, show_node, show_namespace));

    let filtered = match regex {
        Some(r) => ::table::filter(pods_specs, r),
        None => pods_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_pods = filtered.into_iter().map(|pod_spec| pod_spec.0).collect();
    PodList { items: final_pods }
}

/// Build a multi-line string of the specified keyvals
fn keyval_string(keyvals: &Option<serde_json::Map<String, Value>>) -> String {
    let mut buf = String::new();
    if let Some(ref lbs) = keyvals {
        for (key, val) in lbs.iter() {
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
fn print_nodelist(
    mut nodelist: NodeList,
    labels: bool,
    regex: Option<Regex>,
    sort: Option<&str>,
    reverse: bool,
    writer: &mut ClickWriter,
) -> NodeList {
    let mut table = Table::new();
    let mut title_row = row!["####", "Name", "State", "Age"];
    let show_labels = labels
        || sort
            .map(|s| s == "Labels" || s == "labels")
            .unwrap_or(false);
    if show_labels {
        title_row.add_cell(Cell::new("Labels"));
    }
    table.set_titles(title_row);

    if let Some(sortcol) = sort {
        match sortcol {
            "Name" | "name" => nodelist
                .items
                .sort_by(|n1, n2| n1.metadata.name.partial_cmp(&n2.metadata.name).unwrap()),
            "State" | "state" => nodelist.items.sort_by(|n1, n2| {
                let orn1 = n1.status.conditions.iter().find(|c| c.typ == "Ready");
                let orn2 = n2.status.conditions.iter().find(|c| c.typ == "Ready");
                opt_sort(orn1, orn2, |rn1, rn2| {
                    let sort_key1 = if rn1.status == "True" {
                        "Ready"
                    } else {
                        "Not Ready"
                    };
                    let sort_key2 = if rn2.status == "True" {
                        "Ready"
                    } else {
                        "Not Ready"
                    };
                    sort_key1.partial_cmp(sort_key2).unwrap()
                })
            }),
            "Age" | "age" => nodelist.items.sort_by(|n1, n2| {
                opt_sort(
                    n1.metadata.creation_timestamp,
                    n2.metadata.creation_timestamp,
                    |a1, a2| a1.partial_cmp(a2).unwrap(),
                )
            }),
            "Labels" | "labels" => nodelist.items.sort_by(|n1, n2| {
                let n1s = keyval_string(&n1.metadata.labels);
                let n2s = keyval_string(&n2.metadata.labels);
                n1s.partial_cmp(&n2s).unwrap()
            }),
            _ => {
                clickwrite!(
                    writer,
                    "Invalid sort col: {}, this is a bug, please report it",
                    sortcol
                );
            }
        }
    }
    let to_map: Box<dyn Iterator<Item = Node>> = if reverse {
        Box::new(nodelist.items.into_iter().rev())
    } else {
        Box::new(nodelist.items.into_iter())
    };

    let nodes_specs = to_map.map(|node| {
        let mut specs = Vec::new();
        {
            // scope borrows
            let readycond: Option<&NodeCondition> =
                node.status.conditions.iter().find(|c| c.typ == "Ready");
            let (state, state_style) = if let Some(cond) = readycond {
                if cond.status == "True" {
                    ("Ready", "Fg")
                } else {
                    ("Not Ready", "Fr")
                }
            } else {
                ("Unknown", "Fy")
            };

            let state = if let Some(b) = node.spec.unschedulable {
                if b {
                    format!("{}\nSchedulingDisabled", state)
                } else {
                    state.to_owned()
                }
            } else {
                state.to_owned()
            };

            specs.push(CellSpec::new_index());
            specs.push(CellSpec::new_owned(node.metadata.name.clone()));
            specs.push(CellSpec::with_style_owned(state, state_style));
            specs.push(CellSpec::new_owned(time_since(
                node.metadata.creation_timestamp.unwrap(),
            )));
            if show_labels {
                specs.push(CellSpec::new_owned(keyval_string(&node.metadata.labels)));
            }
        }
        (node, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(nodes_specs, r),
        None => nodes_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_nodes = filtered.into_iter().map(|node_spec| node_spec.0).collect();
    NodeList { items: final_nodes }
}

/// Print out the specified list of deployments in a pretty format
fn print_deployments(
    mut deplist: DeploymentList,
    show_labels: bool,
    regex: Option<Regex>,
    sort: Option<&str>,
    reverse: bool,
    writer: &mut ClickWriter,
) -> DeploymentList {
    let mut table = Table::new();
    let mut title_row = row![
        "####",
        "Name",
        "Desired",
        "Current",
        "Up To Date",
        "Available",
        "Age"
    ];
    let show_labels = show_labels
        || sort
            .map(|s| s == "Labels" || s == "labels")
            .unwrap_or(false);
    if show_labels {
        title_row.add_cell(Cell::new("Labels"));
    }
    table.set_titles(title_row);

    if let Some(sortcol) = sort {
        match sortcol {
            "Name" | "name" => deplist
                .items
                .sort_by(|d1, d2| d1.metadata.name.partial_cmp(&d2.metadata.name).unwrap()),
            "Desired" | "desired" => deplist
                .items
                .sort_by(|d1, d2| d1.spec.replicas.partial_cmp(&d2.spec.replicas).unwrap()),
            "Current" | "current" => deplist
                .items
                .sort_by(|d1, d2| d1.status.replicas.partial_cmp(&d2.status.replicas).unwrap()),
            "UpToDate" | "uptodate" => deplist
                .items
                .sort_by(|d1, d2| d1.status.updated.partial_cmp(&d2.status.updated).unwrap()),
            "Available" | "available" => deplist.items.sort_by(|d1, d2| {
                d1.status
                    .available
                    .partial_cmp(&d2.status.available)
                    .unwrap()
            }),
            "Age" | "age" => deplist.items.sort_by(|p1, p2| {
                opt_sort(
                    p1.metadata.creation_timestamp,
                    p2.metadata.creation_timestamp,
                    |a1, a2| a1.partial_cmp(a2).unwrap(),
                )
            }),
            "Labels" | "labels" => deplist.items.sort_by(|p1, p2| {
                let p1s = keyval_string(&p1.metadata.labels);
                let p2s = keyval_string(&p2.metadata.labels);
                p1s.partial_cmp(&p2s).unwrap()
            }),
            _ => {
                clickwrite!(
                    writer,
                    "Invalid sort col: {}, this is a bug, please report it",
                    sortcol
                );
            }
        }
    }

    let to_map: Box<dyn Iterator<Item = Deployment>> = if reverse {
        Box::new(deplist.items.into_iter().rev())
    } else {
        Box::new(deplist.items.into_iter())
    };

    let deps_specs = to_map.map(|dep| {
        let mut specs = Vec::new();
        specs.push(CellSpec::new_index());
        specs.push(CellSpec::new_owned(dep.metadata.name.clone()));
        specs.push(CellSpec::with_align_owned(
            format!("{}", dep.spec.replicas),
            format::Alignment::CENTER,
        ));
        specs.push(CellSpec::with_align_owned(
            format!("{}", dep.status.replicas),
            format::Alignment::CENTER,
        ));
        specs.push(CellSpec::with_align_owned(
            format!("{}", dep.status.updated),
            format::Alignment::CENTER,
        ));
        specs.push(CellSpec::with_align_owned(
            format!("{}", dep.status.available),
            format::Alignment::CENTER,
        ));
        specs.push(CellSpec::new_owned(time_since(
            dep.metadata.creation_timestamp.unwrap(),
        )));
        if show_labels {
            specs.push(CellSpec::new_owned(keyval_string(&dep.metadata.labels)));
        }
        (dep, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(deps_specs, r),
        None => deps_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_deps = filtered.into_iter().map(|dep_spec| dep_spec.0).collect();
    DeploymentList { items: final_deps }
}

// service utility functions
fn get_external_ip(service: &Service) -> String {
    if let Some(ref eips) = service.spec.external_ips {
        shorten_to(eips.join(", "), 18)
    } else {
        // look in the status for the elb name
        if let Some(ing_val) = service.status.pointer("/loadBalancer/ingress") {
            if let Some(ing_arry) = ing_val.as_array() {
                let strs: Vec<&str> = ing_arry
                    .iter()
                    .map(|v| {
                        if let Some(hv) = v.get("hostname") {
                            hv.as_str().unwrap_or("")
                        } else if let Some(ipv) = v.get("ip") {
                            ipv.as_str().unwrap_or("")
                        } else {
                            ""
                        }
                    })
                    .collect();
                let s = strs.join(", ");
                shorten_to(s, 18)
            } else {
                "<none>".to_owned()
            }
        } else {
            "<none>".to_owned()
        }
    }
}

fn get_ports(service: &Service) -> String {
    let port_strs: Vec<String> = if let Some(ref ports) = service.spec.ports {
        ports
            .iter()
            .map(|p| {
                if let Some(np) = p.node_port {
                    format!("{}:{}/{}", p.port, np, p.protocol)
                } else {
                    format!("{}/{}", p.port, p.protocol)
                }
            })
            .collect()
    } else {
        vec!["<none>".to_owned()]
    };
    port_strs.join(",")
}

/// Print out the specified list of services in a pretty format
fn print_servicelist(
    servlist: ServiceList,
    regex: Option<Regex>,
    show_labels: bool,
    show_namespace: bool,
    sort: Option<&str>,
    reverse: bool,
    writer: &mut ClickWriter,
) -> ServiceList {
    let mut table = Table::new();
    let mut title_row = row![
        "####",
        "Name",
        "ClusterIP",
        "External IPs",
        "Port(s)",
        "Age"
    ];

    let show_labels = show_labels
        || sort
            .map(|s| s == "Labels" || s == "labels")
            .unwrap_or(false);
    let show_namespace = show_namespace
        || sort
            .map(|s| s == "Namespace" || s == "namespace")
            .unwrap_or(false);

    if show_labels {
        title_row.add_cell(Cell::new("Labels"));
    }
    if show_namespace {
        title_row.add_cell(Cell::new("Namespace"));
    }
    table.set_titles(title_row);

    let extipsandports: Vec<(String, String)> = servlist
        .items
        .iter()
        .map(|s| (get_external_ip(s), get_ports(s)))
        .collect();
    let mut servswithipportss: Vec<(Service, (String, String))> =
        servlist.items.into_iter().zip(extipsandports).collect();

    if let Some(sortcol) = sort {
        match sortcol {
            "Name" | "name" => servswithipportss
                .sort_by(|s1, s2| s1.0.metadata.name.partial_cmp(&s2.0.metadata.name).unwrap()),
            "Age" | "age" => servswithipportss.sort_by(|s1, s2| {
                opt_sort(
                    s1.0.metadata.creation_timestamp,
                    s2.0.metadata.creation_timestamp,
                    |a1, a2| a1.partial_cmp(a2).unwrap(),
                )
            }),
            "Labels" | "labels" => servswithipportss.sort_by(|s1, s2| {
                let s1s = keyval_string(&s1.0.metadata.labels);
                let s2s = keyval_string(&s2.0.metadata.labels);
                s1s.partial_cmp(&s2s).unwrap()
            }),
            "Namespace" | "namespace" => servswithipportss.sort_by(|s1, s2| {
                opt_sort(
                    s1.0.metadata.namespace.as_ref(),
                    s2.0.metadata.namespace.as_ref(),
                    |s1n, s2n| s1n.partial_cmp(s2n).unwrap(),
                )
            }),
            "ClusterIP" | "clusterip" => servswithipportss.sort_by(|s1, s2| {
                opt_sort(
                    s1.0.spec.cluster_ip.as_ref(),
                    s2.0.spec.cluster_ip.as_ref(),
                    |s1cip, s2cip| s1cip.partial_cmp(s2cip).unwrap(),
                )
            }),
            "ExternalIP" | "externalip" => {
                servswithipportss.sort_by(|s1, s2| (s1.1).0.partial_cmp(&(s2.1).0).unwrap())
            }
            "Ports" | "ports" => {
                servswithipportss.sort_by(|s1, s2| (s1.1).1.partial_cmp(&(s2.1).1).unwrap())
            }
            _ => {
                clickwrite!(
                    writer,
                    "Invalid sort col: {}, this is a bug, please report it",
                    sortcol
                );
            }
        }
    }

    let to_map: Box<dyn Iterator<Item = (Service, (String, String))>> = if reverse {
        Box::new(servswithipportss.into_iter().rev())
    } else {
        Box::new(servswithipportss.into_iter())
    };

    let service_specs = to_map.map(|(service, eipp)| {
        let mut specs = Vec::new();

        specs.push(CellSpec::new_index());

        specs.push(CellSpec::new_owned(service.metadata.name.clone()));
        specs.push(CellSpec::new_owned(
            service
                .spec
                .cluster_ip
                .as_ref()
                .unwrap_or(&"<none>".to_owned())
                .to_string(),
        ));

        specs.push(CellSpec::new_owned(eipp.0));
        specs.push(CellSpec::new_owned(eipp.1));

        specs.push(CellSpec::new_owned(time_since(
            service.metadata.creation_timestamp.unwrap(),
        )));

        if show_labels {
            specs.push(CellSpec::new_owned(keyval_string(&service.metadata.labels)));
        }

        if show_namespace {
            specs.push(CellSpec::new_owned(match service.metadata.namespace {
                Some(ref ns) => ns.clone(),
                None => "[Unknown]".to_owned(),
            }));
        }

        (service, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(service_specs, r),
        None => service_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_services = filtered
        .into_iter()
        .map(|service_spec| service_spec.0)
        .collect();
    ServiceList {
        items: final_services,
    }
}

/// Print out the specified list of deployments in a pretty format
fn print_namespaces(nslist: &NamespaceList, regex: Option<Regex>, writer: &mut ClickWriter) {
    let mut table = Table::new();
    table.set_titles(row!["Name", "Status", "Age"]);

    let ns_specs = nslist.items.iter().map(|ns| {
        let mut specs = Vec::new();
        specs.push(CellSpec::new(ns.metadata.name.as_str()));
        let ps = ns.status.phase.as_str();
        specs.push(CellSpec::with_style(ps, phase_style_str(ps)));
        specs.push(CellSpec::new_owned(time_since(
            ns.metadata.creation_timestamp.unwrap(),
        )));
        (ns, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(ns_specs, r),
        None => ns_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);
}

// Command defintions below.  See documentation for the command! macro for an explanation of
// arguments passed here

command!(
    Quit,
    "quit",
    "Quit click",
    identity,
    vec!["q", "quit", "exit"],
    noop_complete!(),
    |_, env, _| {
        env.quit = true;
    }
);

command!(
    Context,
    "context",
    "Set the current context (will clear any selected pod). \
     With no argument, lists available contexts.",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("context")
            .help("The name of the context")
            .required(false)
            .index(1)
    ),
    vec!["ctx", "context"],
    vec![&completer::context_complete],
    |matches, env, writer| {
        if matches.is_present("context") {
            let context = matches.value_of("context");
            if let (&Some(ref k), Some(c)) = (&env.kluster, context) {
                if k.name == c {
                    // no-op if we're already in the specified context
                    return;
                }
            }
            env.set_context(context);
            env.clear_current();
        } else {
            let mut contexts: Vec<&String> = env.config.contexts.keys().collect();
            contexts.sort();
            let mut table = Table::new();
            table.set_titles(row!["Context", "Api Server Address"]);
            let ctxs = contexts
                .iter()
                .map(|context| {
                    let mut row = Vec::new();
                    let cluster = match env.config.clusters.get(*context) {
                        Some(c) => c.server.as_str(),
                        None => "[no cluster for context]",
                    };
                    row.push(CellSpec::with_style(context, "FR"));
                    row.push(CellSpec::new(cluster));
                    (context, row)
                })
                .collect();
            table.set_format(TBLFMT.clone());
            ::table::print_table(&mut table, &ctxs, writer);
        }
    }
);

command!(
    Contexts,
    "contexts",
    "List available contexts",
    identity,
    vec!["contexts", "ctxs"],
    noop_complete!(),
    |_, env, writer| {
        let mut contexts: Vec<&String> = env.get_contexts().iter().map(|kv| kv.0).collect();
        contexts.sort();
        for context in contexts.iter() {
            clickwrite!(writer, "{}\n", context);
        }
    }
);

command!(
    Clear,
    "clear",
    "Clear the currently selected kubernetes object",
    identity,
    vec!["clear"],
    noop_complete!(),
    |_, env, _| {
        env.clear_current();
    }
);

command!(
    Namespace,
    "namespace",
    "Set the current namespace (no argument to clear namespace)",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("namespace")
            .help("The namespace to use")
            .required(false)
            .index(1)
    ),
    vec!["ns", "namespace"],
    vec![&completer::namespace_completer],
    |matches, env, _| {
        let ns = matches.value_of("namespace");
        env.set_namespace(ns);
    }
);

command!(
    Pods,
    "pods",
    "Get pods (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("label")
                .short("l")
                .long("label")
                .help("Get pods with specified label selector (example: app=kinesis2prom)")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter pods by the specified regex")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("showlabels")
                .short("L")
                .long("labels")
                .help("Show pod labels as column in output")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("showannot")
                .short("A")
                .long("show-annotations")
                .help("Show pod annotations as column in output")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("shownode")
                .short("n")
                .long("show-node")
                .help("Show node pod is on as column in output")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("sort")
                .short("s")
                .long("sort")
                .help(
                    "Sort by specified column (if column isn't shown by default, it will \
                     be shown)"
                )
                .takes_value(true)
                .possible_values(&[
                    "Name",
                    "name",
                    "Ready",
                    "ready",
                    "Phase",
                    "phase",
                    "Age",
                    "age",
                    "Restarts",
                    "restarts",
                    "Labels",
                    "labels",
                    "Annotations",
                    "annotations",
                    "Node",
                    "node",
                    "Namespace",
                    "namespace"
                ])
        )
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false)
        ),
    vec!["pods"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

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

        if let ObjectSelection::Single(obj) = env.current_selection() {
            if obj.is(ObjType::Node) {
                if pushed_label {
                    urlstr.push('&');
                } else {
                    urlstr.push('?');
                }
            }
            urlstr.push_str("fieldSelector=spec.nodeName=");
            urlstr.push_str(obj.name());
        }

        let pl: Option<PodList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));

        match pl {
            Some(l) => {
                let end_list = print_podlist(
                    l,
                    matches.is_present("showlabels"),
                    matches.is_present("showannot"),
                    matches.is_present("shownode"),
                    env.namespace.is_none(),
                    regex,
                    matches.value_of("sort"),
                    matches.is_present("reverse"),
                    writer,
                );
                env.set_lastlist(LastList::PodList(end_list));
            }
            None => env.set_lastlist(LastList::None),
        }
    }
);

// logs helper commands
fn pick_container<'a>(obj: &'a KObj, writer: &mut ClickWriter) -> &'a str {
    match obj.typ {
        ObjType::Pod { ref containers, .. } => {
            if containers.len() > 1 {
                clickwrite!(writer, "Pod has multiple containers, picking the first one");
            }
            containers[0].as_str()
        }
        _ => unreachable!(),
    }
}

command!(
    Logs,
    "logs",
    "Get logs from a container in the current pod",
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("container")
                .help("Specify which container to get logs from")
                .required(false)
                .index(1),
        )
        .arg(
            Arg::with_name("follow")
                .short("f")
                .long("follow")
                .help("Follow the logs as new records arrive (stop with ^C)")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("tail")
                .short("t")
                .long("tail")
                .validator(valid_u32)
                .help("Number of lines from the end of the logs to show")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("previous")
                .short("p")
                .long("previous")
                .help("Return previous terminated container logs")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("since")
                .long("since")
                .conflicts_with("sinceTime")
                .validator(valid_duration)
                .help(
                    "Only return logs newer than specified relative duration,
 e.g. 5s, 2m, 3m5s, 1h2min5sec",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sinceTime")
                .long("since-time")
                .conflicts_with("since")
                .validator(valid_date)
                .help(
                    "Only return logs newer than specified RFC3339 date. Eg:
 1996-12-19T16:39:57-08:00",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("editor")
                .long("editor")
                .short("e")
                .conflicts_with("follow")
                .help(
                    "Open fetched logs in an editor rather than printing them out. with \
                     --editor ARG, ARG is used as the editor command, otherwise the \
                     $EDITOR environment variable is used.",
                )
                .takes_value(true)
                .min_values(0),
        )
    },
    vec!["logs"],
    vec![&completer::container_completer],
    #[allow(clippy::cognitive_complexity)]
    |matches, env, writer| {
        let obj = match env.current_selection() {
            ObjectSelection::Single(obj) => obj,
            ObjectSelection::Range(_) => {
                clickwrite!(writer, "No logs on ranges yet\n");
                return;
            }
            ObjectSelection::None => {
                clickwrite!(writer, "Need an active selection for logs\n");
                return;
            }
        };
        if !obj.is_pod() {
            clickwrite!(writer, "Logs only available on a pod\n");
            return;
        }

        let namespace = match obj.namespace {
            Some(ref ns) => ns,
            None => {
                clickwrite!(
                    writer,
                    "Current pod has no namespace, this shouldn't be possible."
                );
                return;
            }
        };

        let cont = match matches.value_of("container") {
            Some(c) => c,
            None => pick_container(obj, writer),
        };

        let mut url = format!(
            "/api/v1/namespaces/{}/pods/{}/log?container={}",
            namespace,
            obj.name(),
            cont
        );
        if matches.is_present("follow") {
            url.push_str("&follow=true");
        }
        if matches.is_present("previous") {
            url.push_str("&previous=true");
        }
        if matches.is_present("tail") {
            url.push_str(format!("&tailLines={}", matches.value_of("tail").unwrap()).as_str());
        }
        if matches.is_present("since") {
            // all unwraps already validated
            let dur = parse_duration(matches.value_of("since").unwrap()).unwrap();
            url.push_str(format!("&sinceSeconds={}", dur.as_secs()).as_str());
        }
        if matches.is_present("sinceTime") {
            let specified =
                DateTime::parse_from_rfc3339(matches.value_of("sinceTime").unwrap()).unwrap();
            let dur = Utc::now().signed_duration_since(specified.with_timezone(&Utc));
            url.push_str(format!("&sinceSeconds={}", dur.num_seconds()).as_str());
        }
        let timeout = if matches.is_present("follow") {
            None
        } else {
            Some(Duration::new(1, 0))
        };
        let logs_reader = env.run_on_kluster(|k| k.get_read(url.as_str(), timeout));
        if let Some(lreader) = logs_reader {
            let mut reader = BufReader::new(lreader);
            let mut line = String::new();
            env.ctrlcbool.store(false, Ordering::SeqCst);
            if matches.is_present("editor") {
                // We're opening in an editor, save to a temp
                let editor = if let Some(v) = matches.value_of("editor") {
                    v.to_owned()
                } else if let Some(ref e) = env.click_config.editor {
                    e.clone()
                } else {
                    match std::env::var("EDITOR") {
                        Ok(ed) => ed,
                        Err(e) => {
                            clickwrite!(
                                writer,
                                "Could not get EDITOR environment \
                                 variable: {}\n",
                                e.description()
                            );
                            return;
                        }
                    }
                };
                let tmpdir = match env.tempdir {
                    Ok(ref td) => td,
                    Err(ref e) => {
                        clickwrite!(writer, "Failed to create tempdir: {}\n", e.description());
                        return;
                    }
                };
                let file_path = tmpdir.path().join(format!(
                    "{}_{}_{}.log",
                    obj.name(),
                    cont,
                    Local::now().to_rfc3339()
                ));
                match std::fs::File::create(&file_path) {
                    Ok(mut file) => {
                        let mut buffer = [0; 1024];
                        while !env.ctrlcbool.load(Ordering::SeqCst) {
                            match reader.read(&mut buffer[..]) {
                                Ok(amt) => {
                                    if amt == 0 {
                                        break;
                                    }
                                    if let Err(e) = file.write(&buffer[0..amt]) {
                                        clickwrite!(
                                            writer,
                                            "Failed to write to file: {}\n",
                                            e.description()
                                        );
                                        return;
                                    }
                                }
                                Err(e) => {
                                    clickwrite!(
                                        writer,
                                        "Failed to read from remote: {}\n",
                                        e.description()
                                    );
                                }
                            }
                        }
                        // file is created, run $EDITOR on it
                        if let Err(e) = file.flush() {
                            clickwrite!(
                                writer,
                                "Could not flush file: {}, data may be absent.\n",
                                e.description()
                            );
                        }
                        clickwrite!(writer, "Starting editor\n");
                        let expr = if editor.contains(' ') {
                            // split the whitespace
                            let mut eargs: Vec<&str> = editor.split_whitespace().collect();
                            eargs.push(file_path.to_str().unwrap());
                            duct::cmd(eargs[0], &eargs[1..])
                        } else {
                            cmd!(editor, file_path)
                        };
                        if let Err(e) = expr.start() {
                            clickwrite!(writer, "Could not start editor: {}\n", e.description());
                        }
                    }
                    Err(e) => {
                        clickwrite!(writer, "Could not create temp file: {}\n", e.description());
                    }
                }
            } else {
                while !env.ctrlcbool.load(Ordering::SeqCst) {
                    if let Ok(amt) = reader.read_line(&mut line) {
                        if amt > 0 {
                            clickwrite!(writer, "{}", line); // newlines already in line
                            line.clear();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
);

command!(
    Describe,
    "describe",
    "Describe the active kubernetes object.",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the full description in json")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("yaml")
                .short("y")
                .long("yaml")
                .help("Print the full description in yaml")
                .takes_value(false)
        ),
    vec!["describe"],
    noop_complete!(),
    |matches, env, writer| {
        match env.current_selection() {
            ObjectSelection::Single(obj) => obj.describe(&matches, env, writer),
            ObjectSelection::Range(range) => {
                for obj in range.iter() {
                    obj.describe(&matches, env, writer);
                }
            }
            ObjectSelection::None => clickwrite!(writer, "No active object to describe\n"),
        }
    }
);

command!(
    Exec,
    "exec",
    "exec specified command on active pod",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("command")
                .help("The command to execute")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::with_name("container")
                .short("c")
                .long("container")
                .help("Exec in the specified container")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("terminal")
                .short("t")
                .long("terminal")
                .help(
                    "Run the command in a new terminal.  With --terminal ARG, ARG is used as the \
                     terminal command, otherwise the default is used ('set terminal <value>' to \
                     specify default)"
                )
                .takes_value(true)
                .min_values(0)
        ),
    vec!["exec"],
    noop_complete!(),
    |matches, env, writer| {
        let cmd = matches.value_of("command").unwrap(); // safe as required
        if let (Some(ref kluster), Some(ref pod)) =
            (env.kluster.as_ref(), env.current_pod().as_ref())
        {
            let mut contargs = if let Some(container) = matches.value_of("container") {
                vec!["-c", container]
            } else {
                vec![]
            };
            let ns = pod.namespace.as_ref().unwrap();
            if matches.is_present("terminal") {
                let terminal = if let Some(t) = matches.value_of("terminal") {
                    t
                } else if let Some(ref t) = env.click_config.terminal {
                    t
                } else {
                    "xterm -e"
                };
                let mut targs: Vec<&str> = terminal.split_whitespace().collect();
                let mut kubectl_args = vec![
                    "kubectl",
                    "--namespace",
                    ns,
                    "--context",
                    &kluster.name,
                    "exec",
                    "-it",
                    pod.name(),
                ];
                targs.append(&mut kubectl_args);
                targs.append(&mut contargs);
                targs.push(cmd);
                clickwrite!(writer, "Starting in terminal\n");
                if let Err(e) = duct::cmd(targs[0], &targs[1..]).start() {
                    clickwrite!(
                        writer,
                        "Could not launch in terminal: {}\n",
                        e.description()
                    );
                }
            } else {
                let status = Command::new("kubectl")
                    .arg("--namespace")
                    .arg(ns)
                    .arg("--context")
                    .arg(&kluster.name)
                    .arg("exec")
                    .arg("-it")
                    .arg(pod.name())
                    .args(contargs.iter())
                    .arg(cmd)
                    .status()
                    .expect("failed to execute kubectl");
                if !status.success() {
                    write!(stderr(), "kubectl exited abnormally\n").unwrap_or(());
                }
            }
        } else {
            write!(stderr(), "Need an active pod in order to exec.").unwrap_or(());
        }
    }
);

command!(
    Delete,
    "delete",
    "Delete the active object (will ask for confirmation)",
    |clap: App<'static, 'static>| {
        clap.arg(
        Arg::with_name("grace")
            .short("g")
            .long("gracePeriod")
            .help("The duration in seconds before the object should be deleted.")
            .validator(valid_u32)
            .takes_value(true)
    ).arg(Arg::with_name("cascade")
            .short("c")
            .long("cascade")
            .help("If true (the default), dependant objects are deleted. \
                   If false, they are orphaned")
            .validator(valid_bool)
            .takes_value(true)
    ).arg(Arg::with_name("now")
          .long("now")
          .help("If set, resources are signaled for immediate shutdown (same as --grace-period=1)")
          .takes_value(false)
          .conflicts_with("grace")
    ).arg(Arg::with_name("force")
          .long("force")
          .help("Force immediate deletion.  For some resources this may result in inconsistency or \
                 data loss")
          .takes_value(false)
          .conflicts_with("grace")
          .conflicts_with("now")
    )
    },
    vec!["delete"],
    noop_complete!(),
    |matches, env, writer| {
        match env.current_selection() {
            ObjectSelection::Single(obj) => {
                let no_delete_opts = obj.is(ObjType::Service);
                let name = obj.name();
                let namespace = match obj.typ {
                    ObjType::Node => "",
                    _ => match obj.namespace {
                        Some(ref ns) => ns,
                        None => {
                            clickwrite!(writer, "Don't know namespace for {}\n", obj.name());
                            return;
                        }
                    },
                };
                clickwrite!(writer, "Delete {} {} [y/N]? ", obj.type_str(), name);
                io::stdout().flush().expect("Could not flush stdout");
                let mut conf = String::new();
                if io::stdin().read_line(&mut conf).is_ok() {
                    if conf.trim() == "y" || conf.trim() == "yes" {
                        let url = obj.url(namespace);
                        let mut policy = "Foreground";
                        if let Some(cascade) = matches.value_of("cascade") {
                            if !(cascade.parse::<bool>()).unwrap() {
                                // safe as validated
                                policy = "Orphan";
                            }
                        }
                        let delete_body = if no_delete_opts {
                            None
                        } else {
                            let mut delete_body = json!({
                                "kind":"DeleteOptions",
                                "apiVersion":"v1",
                                "propagationPolicy": policy
                            });
                            if let Some(grace) = matches.value_of("grace") {
                                let graceu32 = grace.parse::<u32>().unwrap(); // safe as validated
                                if graceu32 == 0 {
                                    // don't allow zero, make it one.  zero is force delete which
                                    // can mess things up.
                                    delete_body
                                        .as_object_mut()
                                        .unwrap()
                                        .insert("gracePeriodSeconds".to_owned(), json!(1));
                                } else {
                                    // already validated that it's a legit number
                                    delete_body
                                        .as_object_mut()
                                        .unwrap()
                                        .insert("gracePeriodSeconds".to_owned(), json!(graceu32));
                                }
                            } else if matches.is_present("force") {
                                delete_body
                                    .as_object_mut()
                                    .unwrap()
                                    .insert("gracePeriodSeconds".to_owned(), json!(0));
                            } else if matches.is_present("now") {
                                delete_body
                                    .as_object_mut()
                                    .unwrap()
                                    .insert("gracePeriodSeconds".to_owned(), json!(1));
                            }
                            Some(delete_body.to_string())
                        };
                        let result = env.run_on_kluster(|k| k.delete(url.as_str(), delete_body));
                        if let Some(x) = result {
                            if x.status.is_success() {
                                clickwrite!(writer, "Deleted\n");
                            } else {
                                clickwrite!(writer, "Failed to delete: {:?}", x.get_ref());
                            }
                        } else {
                            write!(stderr(), "Failed to delete").unwrap_or(());
                        }
                    } else {
                        clickwrite!(writer, "Not deleting\n");
                    }
                } else {
                    write!(stderr(), "Could not read response, not deleting.").unwrap_or(());
                }
            }
            ObjectSelection::Range(_) => {
                clickwrite!(writer, "Range delete coming soon!\n");
            }
            ObjectSelection::None => {
                clickwrite!(writer, "No active object to delete");
            }
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
            buf.push_str(format!("  Ready:\t{}\n", cont.ready).as_str());

            // find the spec for this container
            let mut spec_it = pod.spec.containers.iter().filter(|cs| cs.name == cont.name);
            if let Some(spec) = spec_it.next() {
                if let Some(ref vols) = spec.volume_mounts {
                    buf.push_str("  Volumes:\n");
                    for vol in vols.iter() {
                        buf.push_str(format!("   {}\n", vol.name).as_str());
                        buf.push_str(format!("    Path:\t{}\n", vol.mount_path).as_str());
                        buf.push_str(
                            format!(
                                "    Sub-Path:\t{}\n",
                                vol.sub_path.as_ref().unwrap_or(&"".to_owned())
                            )
                            .as_str(),
                        );
                        buf.push_str(
                            format!("    Read-Only:\t{}\n", vol.read_only.unwrap_or(false))
                                .as_str(),
                        );
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

command!(
    Containers,
    "containers",
    "List containers on the active pod",
    identity,
    vec!["conts", "containers"],
    noop_complete!(),
    |_matches, env, writer| {
        if let Some(ref pod) = env.current_pod() {
            let url = format!(
                "/api/v1/namespaces/{}/pods/{}",
                pod.namespace.as_ref().unwrap(),
                pod.name()
            );
            let pod_opt: Option<Pod> = env.run_on_kluster(|k| k.get(url.as_str()));
            if let Some(pod) = pod_opt {
                clickwrite!(writer, "{}", containers_string(&pod)); // extra newline in returned string
            }
        } else {
            write!(stderr(), "No active pod").unwrap_or(());
        }
    }
);

fn format_event(event: &Event) -> String {
    format!(
        "{} - {}\n count: {}\n reason: {}\n",
        event.last_timestamp.with_timezone(&Local),
        event.message,
        event.count,
        event.reason
    )
}

command!(
    Events,
    "events",
    "Get events for the active pod",
    identity,
    vec!["events"],
    noop_complete!(),
    |_matches, env, writer| if let Some(ref pod) = env.current_pod() {
        let ns = pod.namespace.as_ref().unwrap();
        let url = format!(
            "/api/v1/namespaces/{}/events?fieldSelector=involvedObject.name={},involvedObject.namespace={}",
            ns, pod.name(), ns
        );
        let oel: Option<EventList> = env.run_on_kluster(|k| k.get(url.as_str()));
        if let Some(el) = oel {
            if !el.items.is_empty() {
                for e in el.items.iter() {
                    clickwrite!(writer, "{}\n", format_event(e));
                }
            } else {
                clickwrite!(writer, "No events\n");
            }
        } else {
            write!(stderr(), "Failed to fetch events\n").unwrap_or(());
        }
    } else {
        write!(stderr(), "No active pod\n").unwrap_or(());
    }
);

command!(
    Nodes,
    "nodes",
    "Get nodes",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("labels")
                .short("L")
                .long("labels")
                .help("include labels in output")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter pods by the specified regex")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("sort")
                .short("s")
                .long("sort")
                .help(
                    "Sort by specified column (if column isn't shown by default, it will \
                     be shown)"
                )
                .takes_value(true)
                .possible_values(&[
                    "Name", "name", "State", "state", "Age", "age", "Labels", "labels",
                ])
        )
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false)
        ),
    vec!["nodes"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let url = "/api/v1/nodes";
        let nl: Option<NodeList> = env.run_on_kluster(|k| k.get(url));
        match nl {
            Some(n) => {
                let final_list = print_nodelist(
                    n,
                    matches.is_present("labels"),
                    regex,
                    matches.value_of("sort"),
                    matches.is_present("reverse"),
                    writer,
                );
                env.set_lastlist(LastList::NodeList(final_list));
            }
            None => env.set_lastlist(LastList::None),
        }
    }
);

command!(
    Services,
    "services",
    "Get services (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("labels")
                .short("L")
                .long("labels")
                .help("include labels in output")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter services by the specified regex")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("sort")
                .short("s")
                .long("sort")
                .help(
                    "Sort by specified column (if column isn't shown by default, it will \
                     be shown)"
                )
                .takes_value(true)
                .possible_values(&[
                    "Name",
                    "name",
                    "ClusterIP",
                    "clusterip",
                    "ExternalIP",
                    "externalip",
                    "Age",
                    "age",
                    "Ports",
                    "ports",
                    "Labels",
                    "labels",
                    "Namespace",
                    "namespace"
                ])
        )
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false)
        ),
    vec!["services"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let url = if let Some(ref ns) = env.namespace {
            format!("/api/v1/namespaces/{}/services", ns)
        } else {
            "/api/v1/services".to_owned()
        };
        let sl: Option<ServiceList> = env.run_on_kluster(|k| k.get(url.as_str()));
        if let Some(s) = sl {
            let filtered = print_servicelist(
                s,
                regex,
                matches.is_present("labels"),
                env.namespace.is_none(),
                matches.value_of("sort"),
                matches.is_present("reverse"),
                writer,
            );
            env.set_lastlist(LastList::ServiceList(filtered));
        } else {
            clickwrite!(writer, "no services\n");
            env.set_lastlist(LastList::None);
        }
    }
);

command!(
    EnvCmd,
    "env",
    "Print information about the current environment",
    identity,
    vec!["env"],
    noop_complete!(),
    |_matches, env, writer| {
        clickwrite!(writer, "{}\n", env);
    }
);

command!(
    SetCmd,
    "set",
    "Set click options. (See 'help completion' and 'help edit_mode' for more information",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("option")
                .help("The click option to set")
                .required(true)
                .index(1)
                .possible_values(&["completion_type", "edit_mode", "editor", "terminal"])
        )
        .arg(
            Arg::with_name("value")
                .help("The value to set the option to")
                .required(true)
                .index(2)
        ),
    vec!["set"],
    vec![&completer::setoptions_values_completer],
    |matches, env, writer| {
        let option = matches.value_of("option").unwrap(); // safe, required
        let value = matches.value_of("value").unwrap(); // safe, required
        let mut failed = false;
        match option {
            "completion_type" => match value {
                "circular" => env.set_completion_type(config::CompletionType::Circular),
                "list" => env.set_completion_type(config::CompletionType::List),
                _ => {
                    write!(
                        stderr(),
                        "Invalid completion type.  Possible values are: [circular, list]\n"
                    )
                    .unwrap_or(());
                    failed = true;
                }
            },
            "edit_mode" => match value {
                "vi" => env.set_edit_mode(config::EditMode::Vi),
                "emacs" => env.set_edit_mode(config::EditMode::Emacs),
                _ => {
                    write!(
                        stderr(),
                        "Invalid edit_mode.  Possible values are: [emacs, vi]\n"
                    )
                    .unwrap_or(());
                    failed = true;
                }
            },
            "editor" => {
                env.set_editor(&Some(value.to_owned()));
            }
            "terminal" => {
                env.set_terminal(&Some(value.to_owned()));
            }
            _ => {
                // this shouldn't happen
                write!(stderr(), "Invalid option\n").unwrap_or(());
                failed = true;
            }
        }
        if !failed {
            clickwrite!(writer, "Set {} to {}\n", option, value);
        }
    }
);

command!(
    Deployments,
    "deployments",
    "Get deployments (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("label")
                .short("l")
                .long("label")
                .help("Get deployments with specified label selector")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter deployments by the specified regex")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("showlabels")
                .short("L")
                .long("labels")
                .help("Show labels as column in output")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("sort")
                .short("s")
                .long("sort")
                .help(
                    "Sort by specified column (if column isn't shown by default, it will \
                     be shown)"
                )
                .takes_value(true)
                .possible_values(&[
                    "Name",
                    "name",
                    "Desired",
                    "desired",
                    "Current",
                    "current",
                    "UpToDate",
                    "uptodate",
                    "Available",
                    "available",
                    "Age",
                    "age",
                    "Labels",
                    "labels"
                ])
        )
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false)
        ),
    vec!["deps", "deployments"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let mut urlstr = if let Some(ref ns) = env.namespace {
            format!("/apis/extensions/v1beta1/namespaces/{}/deployments", ns)
        } else {
            "/apis/extensions/v1beta1/deployments".to_owned()
        };

        if let Some(label_selector) = matches.value_of("label") {
            urlstr.push_str("?labelSelector=");
            urlstr.push_str(label_selector);
        }

        let dl: Option<DeploymentList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));
        match dl {
            Some(d) => {
                let final_list = print_deployments(
                    d,
                    matches.is_present("showlabels"),
                    regex,
                    matches.value_of("sort"),
                    matches.is_present("reverse"),
                    writer,
                );
                env.set_lastlist(LastList::DeploymentList(final_list));
            }
            None => env.set_lastlist(LastList::None),
        }
    }
);

fn print_replicasets(
    list: ReplicaSetList,
    regex: Option<Regex>,
    writer: &mut ClickWriter,
) -> ReplicaSetList {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "Desired", "Current", "Ready"]);
    let rss_specs = list.items.into_iter().map(|rs| {
        let mut specs = Vec::new();
        specs.push(CellSpec::new_index());
        specs.push(CellSpec::new_owned(
            val_str("/metadata/name", &rs, "<none>").into_owned(),
        ));
        specs.push(CellSpec::new_owned(format!(
            "{}",
            val_u64("/spec/replicas", &rs, 0)
        )));
        specs.push(CellSpec::new_owned(format!(
            "{}",
            val_u64("/status/replicas", &rs, 0)
        )));
        specs.push(CellSpec::new_owned(format!(
            "{}",
            val_u64("/status/readyReplicas", &rs, 0)
        )));
        (rs, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(rss_specs, r),
        None => rss_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_rss = filtered.into_iter().map(|rs_spec| rs_spec.0).collect();
    ReplicaSetList { items: final_rss }
}

command!(
    ReplicaSets,
    "replicasets",
    "Get replicasets (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("show_label")
                .short("L")
                .long("labels")
                .help("Show replicaset labels")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter replicasets by the specified regex")
                .takes_value(true)
        ),
    vec!["rs", "replicasets"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let urlstr = if let Some(ref ns) = env.namespace {
            format!("/apis/extensions/v1beta1/namespaces/{}/replicasets", ns)
        } else {
            "/apis/extensions/v1beta1/replicasets".to_owned()
        };

        let rsl: Option<ReplicaSetList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));

        match rsl {
            Some(l) => {
                let final_list = print_replicasets(l, regex, writer);
                env.set_lastlist(LastList::ReplicaSetList(final_list));
            }
            None => {
                env.set_lastlist(LastList::None);
            }
        }
    }
);

fn print_statefulsets(
    list: StatefulSetList,
    regex: Option<Regex>,
    writer: &mut ClickWriter,
) -> StatefulSetList {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "Desired", "Current", "Ready"]);
    let statefulsets_specs = list.items.into_iter().map(|statefulset| {
        let mut specs = Vec::new();
        specs.push(CellSpec::new_index());
        specs.push(CellSpec::new_owned(
            val_str("/metadata/name", &statefulset, "<none>").into_owned(),
        ));
        specs.push(CellSpec::new_owned(format!(
            "{}",
            val_u64("/spec/replicas", &statefulset, 0)
        )));
        specs.push(CellSpec::new_owned(format!(
            "{}",
            val_u64("/status/currentReplicas", &statefulset, 0)
        )));
        specs.push(CellSpec::new_owned(format!(
            "{}",
            val_u64("/status/readyReplicas", &statefulset, 0)
        )));
        (statefulset, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(statefulsets_specs, r),
        None => statefulsets_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_statefulsets = filtered
        .into_iter()
        .map(|statefulset_spec| statefulset_spec.0)
        .collect();

    StatefulSetList {
        items: final_statefulsets,
    }
}

command!(
    StatefulSets,
    "statefulsets",
    "Get statefulsets (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("show_label")
                .short("L")
                .long("labels")
                .help("Show statefulsets labels")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter statefulsets by the specified regex")
                .takes_value(true)
        ),
    vec!["ss", "statefulsets"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let urlstr = if let Some(ref ns) = env.namespace {
            format!("/apis/apps/v1beta1/namespaces/{}/statefulsets", ns)
        } else {
            "/apis/apps/v1beta1/statefulsets".to_owned()
        };

        let statefulset_list: Option<StatefulSetList> =
            env.run_on_kluster(|k| k.get(urlstr.as_str()));

        match statefulset_list {
            Some(l) => {
                let final_list = print_statefulsets(l, regex, writer);
                env.set_lastlist(LastList::StatefulSetList(final_list));
            }
            None => {
                env.set_lastlist(LastList::None);
            }
        }
    }
);

fn print_configmaps(
    list: ConfigMapList,
    regex: Option<Regex>,
    writer: &mut ClickWriter,
) -> ConfigMapList {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "Data", "Age"]);
    let cm_specs = list.items.into_iter().map(|cm| {
        let mut specs = Vec::new();
        let metadata: Metadata = get_val_as("/metadata", &cm).unwrap();
        specs.push(CellSpec::new_index());
        specs.push(CellSpec::new_owned(metadata.name));
        let data_count = val_item_count("/data", &cm);
        specs.push(CellSpec::new_owned(format!("{}", data_count)));
        specs.push(CellSpec::new_owned(time_since(
            metadata.creation_timestamp.unwrap(),
        )));
        (cm, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(cm_specs, r),
        None => cm_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_rss = filtered.into_iter().map(|cm_spec| cm_spec.0).collect();
    ConfigMapList { items: final_rss }
}

command!(
    ConfigMaps,
    "configmaps",
    "Get configmaps (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("show_label")
                .short("L")
                .long("labels")
                .help("Show replicaset labels")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter replicasets by the specified regex")
                .takes_value(true)
        ),
    vec!["cm", "configmaps"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let urlstr = if let Some(ref ns) = env.namespace {
            format!("/api/v1/namespaces/{}/configmaps", ns)
        } else {
            "/api/v1/configmaps".to_owned()
        };

        let cml: Option<ConfigMapList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));

        match cml {
            Some(l) => {
                let final_list = print_configmaps(l, regex, writer);
                env.set_lastlist(LastList::ConfigMapList(final_list));
            }
            None => {
                env.set_lastlist(LastList::None);
            }
        }
    }
);

fn print_secrets(list: SecretList, regex: Option<Regex>, writer: &mut ClickWriter) -> SecretList {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "Type", "Data", "Age"]);
    let rss_specs = list.items.into_iter().map(|rs| {
        let mut specs = Vec::new();

        let metadata: Metadata = get_val_as("/metadata", &rs).unwrap();

        specs.push(CellSpec::new_index());
        specs.push(CellSpec::new_owned(metadata.name));
        specs.push(CellSpec::new_owned(
            val_str("/type", &rs, "<none>").into_owned(),
        ));
        specs.push(CellSpec::new_owned(
            val_item_count("/data", &rs).to_string(),
        ));
        specs.push(CellSpec::new_owned(time_since(
            metadata.creation_timestamp.unwrap(),
        )));
        (rs, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(rss_specs, r),
        None => rss_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_rss = filtered.into_iter().map(|rs_spec| rs_spec.0).collect();
    SecretList { items: final_rss }
}

command!(
    Secrets,
    "secrets",
    "Get secrets (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("show_label")
                .short("L")
                .long("labels")
                .help("Show secret labels")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter secrets by the specified regex")
                .takes_value(true)
        ),
    vec!["secrets"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let urlstr = if let Some(ref ns) = env.namespace {
            format!("/api/v1/namespaces/{}/secrets", ns)
        } else {
            "/api/v1/secrets".to_owned()
        };

        let sl: Option<SecretList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));

        match sl {
            Some(l) => {
                let final_list = print_secrets(l, regex, writer);
                env.set_lastlist(LastList::SecretList(final_list));
            }
            None => {
                env.set_lastlist(LastList::None);
            }
        }
    }
);

command!(
    Namespaces,
    "namespaces",
    "Get namespaces in current context",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("regex")
            .short("r")
            .long("regex")
            .help("Filter namespaces by the specified regex")
            .takes_value(true)
    ),
    vec!["namespaces"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let nl: Option<NamespaceList> = env.run_on_kluster(|k| k.get("/api/v1/namespaces"));

        if let Some(l) = nl {
            print_namespaces(&l, regex, writer);
        }
    }
);

command!(
    UtcCmd,
    "utc",
    "Print current time in UTC",
    identity,
    vec!["utc"],
    noop_complete!(),
    |_, _, writer| {
        clickwrite!(writer, "{}\n", Utc::now());
    }
);

command!(
    PortForward,
    "port-forward",
    "Forward one (or more) local ports to the currently active pod",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("ports")
                .help("the ports to forward")
                .multiple(true)
                .validator(|s: String| {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() > 2 {
                        Err(format!(
                            "Invalid port specification '{}', can only contain one ':'",
                            s
                        ))
                    } else {
                        for part in parts {
                            if part != "" {
                                if let Err(e) = part.parse::<u32>() {
                                    return Err(e.description().to_owned());
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
    |matches, env, writer| {
        let ports: Vec<_> = matches.values_of("ports").unwrap().collect();

        let (pod, ns) = {
            let epod = env.current_pod();
            match epod {
                Some(p) => (
                    p.name().to_string(),
                    p.namespace.as_ref().unwrap().to_string(),
                ),
                None => {
                    write!(stderr(), "No active pod").unwrap_or(());
                    return;
                }
            }
        };

        let context = if let Some(ref kluster) = env.kluster {
            kluster.name.clone()
        } else {
            write!(stderr(), "No active context").unwrap_or(());
            return;
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
                                write!(stderr(), "Error reading child output: {}", e.description())
                                    .unwrap_or(());
                                break;
                            }
                        }
                    }
                });

                let pvec: Vec<String> = ports.iter().map(|s| (*s).to_owned()).collect();
                clickwrite!(writer, "Forwarding port(s): {}\n", pvec.join(", "));

                env.add_port_forward(env::PortForward {
                    child: child,
                    pod: pod,
                    ports: pvec,
                    output: output,
                });
            }
            Err(e) => {
                write!(
                    stderr(),
                    "Couldn't execute kubectl, not forwarding.  Error is: {}",
                    e.description()
                )
                .unwrap_or(());
            }
        }
    }
);

/// Print out port forwards found in iterator
fn print_pfs(pfs: std::slice::Iter<env::PortForward>) {
    let mut table = Table::new();
    table.set_titles(row!["####", "Pod", "Ports"]);
    for (i, pf) in pfs.enumerate() {
        let mut row = Vec::new();
        row.push(Cell::new_align(
            format!("{}", i).as_str(),
            format::Alignment::RIGHT,
        ));
        row.push(Cell::new(pf.pod.as_str()));
        row.push(Cell::new(pf.ports.join(", ").as_str()));

        // TODO: Add this when try_wait stabalizes
        // let status =
        //     match pf.child.try_wait() {
        //         Ok(Some(stat)) => format!("Exited with code {}", stat),
        //         Ok(None) => format!("Running"),
        //         Err(e) => format!("Error: {}", e.description()),
        //     };
        // row.push(Cell::new(status.as_str()));

        table.add_row(Row::new(row));
    }
    table.set_format(TBLFMT.clone());
    table.printstd();
}

command!(
    PortForwards,
    "port-forwards",
    "List or control active port forwards.  Default is to list.",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("action")
                .help("Action to take")
                .required(false)
                .possible_values(&["list", "output", "stop"])
                .index(1)
        )
        .arg(
            Arg::with_name("index")
                .help("Index (from 'port-forwards list') of port forward to take action on")
                .validator(|s: String| s
                    .parse::<usize>()
                    .map(|_| ())
                    .map_err(|e| e.description().to_owned()))
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
                        clickwrite!(writer, " Output:\n{}", *pf.output.lock().unwrap());
                    }
                }
                None => {
                    write!(stderr(), "Invalid index (try without args to get a list)")
                        .unwrap_or(());
                    return;
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
                                clickwrite!(writer, "Stopped\n");
                            }
                            Err(e) => {
                                write!(stderr(), "Failed to stop: {}", e.description())
                                    .unwrap_or(());
                            }
                        }
                    } else {
                        clickwrite!(writer, "Not stopping\n");
                    }
                } else {
                    write!(stderr(), "Could not read response, not stopping.").unwrap_or(());
                }
            } else {
                clickwrite!(writer, "\n"); // just flush the above description
            }
        } else {
            print_pfs(env.get_port_forwards());
        }
    }
);

command!(
    Jobs,
    "jobs",
    "Get jobs (in current namespace if set)",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("label")
                .short("l")
                .long("label")
                .help("Get jobs with specified label selector")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter jobs by the specified regex")
                .takes_value(true)
        ),
    vec!["job", "jobs"],
    noop_complete!(),
    |matches, env, writer| {
        let regex = match ::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let mut urlstr = if let Some(ref ns) = env.namespace {
            format!("/apis/batch/v1/namespaces/{}/jobs", ns)
        } else {
            "/apis/batch/v1/jobs".to_owned()
        };

        if let Some(label_selector) = matches.value_of("label") {
            urlstr.push_str("?labelSelector=");
            urlstr.push_str(label_selector);
        }

        let jl: Option<JobList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));
        match jl {
            Some(j) => {
                let final_list = print_jobs(j, matches.is_present("labels"), regex, writer);
                env.set_lastlist(LastList::JobList(final_list));
            }
            None => env.set_lastlist(LastList::None),
        }
    }
);

fn print_jobs(
    joblist: JobList,
    _show_labels: bool,
    regex: Option<Regex>,
    writer: &mut ClickWriter,
) -> JobList {
    let mut table = Table::new();
    table.set_titles(row!["####", "Name", "Desired", "Sucessful", "Age"]);
    let jobs_specs = joblist.items.into_iter().map(|job| {
        let mut specs = Vec::new();
        let metadata: Metadata = get_val_as("/metadata", &job).unwrap();

        specs.push(CellSpec::new_index());
        specs.push(CellSpec::new_owned(metadata.name.clone()));
        specs.push(CellSpec::new_owned(
            get_val_as::<u32>("/spec/parallelism", &job)
                .unwrap()
                .to_string(),
        ));
        specs.push(CellSpec::new_owned(
            get_val_as::<u32>("/spec/completions", &job)
                .unwrap()
                .to_string(),
        ));
        specs.push(CellSpec::new_owned(time_since(
            metadata.creation_timestamp.unwrap(),
        )));

        (job, specs)
    });

    let filtered = match regex {
        Some(r) => ::table::filter(jobs_specs, r),
        None => jobs_specs.collect(),
    };

    ::table::print_table(&mut table, &filtered, writer);

    let final_jobs = filtered.into_iter().map(|job_spec| job_spec.0).collect();
    JobList { items: final_jobs }
}

command!(
    Alias,
    "alias",
    "Define or display aliases",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("alias")
                .help(
                    "the short version of the command.\nCannot be 'alias', 'unalias', or a number."
                )
                .validator(|s: String| {
                    if s == "alias" || s == "unalias" || s.parse::<usize>().is_ok() {
                        Err("alias cannot be \"alias\", \"unalias\", or a number".to_owned())
                    } else {
                        Ok(())
                    }
                })
                .required(false)
                .requires("expanded")
        )
        .arg(
            Arg::with_name("expanded")
                .help("what the short version of the command should expand to")
                .required(false)
                .requires("alias")
        )
        .after_help(
            "An alias is a substitution rule.  When click encounters an alias at the start of a
command, it will substitue the expanded version for what was typed.

As with Bash: The first word of the expansion is tested for aliases, but a word that is identical to
an alias being expanded is not expanded a second time.  So one can alias logs to \"logs -e\", for
instance, without causing infinite expansion.

Examples:
  # Display current aliases
  alias

  # alias p to pods
  alias p pods

  # alias pn to get pods with nginx in the name
  alias pn \"pods -r nginx\"

  # alias el to run logs and grep for ERROR
  alias el \"logs | grep ERROR\""
        ),
    vec!["alias", "aliases"],
    noop_complete!(),
    |matches, env, writer| {
        if matches.is_present("alias") {
            let alias = matches.value_of("alias").unwrap(); // safe, checked above
            let expanded = matches.value_of("expanded").unwrap(); // safe, required with alias
            env.add_alias(config::Alias {
                alias: alias.to_owned(),
                expanded: expanded.to_owned(),
            });
            clickwrite!(writer, "aliased {} = '{}'\n", alias, expanded);
        } else {
            for alias in env.click_config.aliases.iter() {
                clickwrite!(writer, "alias {} = '{}'\n", alias.alias, alias.expanded);
            }
        }
    }
);

command!(
    Unalias,
    "unalias",
    "Remove an alias",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("alias")
            .help("Short version of alias to remove")
            .required(true)
    ),
    vec!["unalias"],
    noop_complete!(),
    |matches, env, writer| {
        let alias = matches.value_of("alias").unwrap(); // safe, required
        if env.remove_alias(alias) {
            clickwrite!(writer, "unaliased: {}\n", alias);
        } else {
            clickwrite!(writer, "no such alias: {}\n", alias);
        }
    }
);
