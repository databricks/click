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

use crate::completer;
use crate::env::Env;

use crate::kube::{Service, ServiceList};
use crate::output::ClickWriter;
use crate::table::{opt_sort, CellSpec};
//use crate::values::{get_val_as, val_item_count, val_str}; //, val_u64};

use ansi_term::Colour::Yellow;

use chrono::offset::Utc;
use chrono::DateTime;
use clap::{App, AppSettings, Arg, ArgMatches};
//use humantime::parse_duration;

use prettytable::Cell;
use prettytable::{format, Table};
use regex::Regex;
use rustyline::completion::Pair as RustlinePair;
use serde_json::Value;

use std::array::IntoIter;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{stderr, Write};
use std::iter::Iterator;

lazy_static! {
    pub static ref TBLFMT: format::TableFormat = format::FormatBuilder::new()
        .separators(
            &[format::LinePosition::Title, format::LinePosition::Bottom],
            format::LineSeparator::new('-', '+', '+', '+')
        )
        .padding(1, 1)
        .build();
}

pub trait Cmd {
    // break if returns true
    fn exec(
        &self,
        env: &mut Env,
        args: &mut dyn Iterator<Item = &str>,
        writer: &mut ClickWriter,
    ) -> bool;
    fn is(&self, l: &str) -> bool;
    fn get_name(&self) -> &'static str;
    fn try_complete(&self, index: usize, prefix: &str, env: &Env) -> Vec<RustlinePair>;
    fn try_completed_named(
        &self,
        index: usize,
        opt: &str,
        prefix: &str,
        env: &Env,
    ) -> Vec<RustlinePair>;
    fn complete_option(&self, prefix: &str) -> Vec<RustlinePair>;
    fn write_help(&self, writer: &mut ClickWriter);
    fn about(&self) -> &'static str;
}

/// Get the start of a clap object
pub fn start_clap(
    name: &'static str,
    about: &'static str,
    aliases: &'static str,
    trailing_var_arg: bool,
) -> App<'static, 'static> {
    let app = App::new(name)
        .about(about)
        .before_help(aliases)
        .setting(AppSettings::NoBinaryName)
        .setting(AppSettings::DisableVersion)
        .setting(AppSettings::ColoredHelp);
    if trailing_var_arg {
        app.setting(AppSettings::TrailingVarArg)
    } else {
        app
    }
}

/// Run specified closure with the given matches, or print error.  Return true if execed,
/// false on err
pub fn exec_match<F>(
    clap: &RefCell<App<'static, 'static>>,
    env: &mut Env,
    args: &mut dyn Iterator<Item = &str>,
    writer: &mut ClickWriter,
    func: F,
) -> bool
where
    F: FnOnce(ArgMatches, &mut Env, &mut ClickWriter),
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
            clickwriteln!(writer, "{}", err.message);
            false
        }
    }
}

macro_rules! noop_complete {
    () => {
        vec![]
    };
}

macro_rules! no_named_complete {
    () => {
        HashMap::new()
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
/// * named_cmplters: a map of argument -> completer for completing named arguments
/// * cmd_expr: a closure taking matches, env, and writer that runs to execute the command
/// * trailing_var_arg: set the "TrailingVarArg" setting for clap (see clap docs, default false)
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
///         no_named_complete!(),
///         |matches, env, writer| {env.quit = true;}
/// );
/// # }
/// ```
macro_rules! command {
    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $aliases:expr, $cmplters: expr,
     $named_cmplters: expr, $cmd_expr:expr) => {
        command!(
            $cmd_name,
            $name,
            $about,
            $extra_args,
            $aliases,
            $cmplters,
            $named_cmplters,
            $cmd_expr,
            false
        );
    };

    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $aliases:expr, $cmplters: expr,
     $named_cmplters: expr, $cmd_expr:expr, $trailing_var_arg: expr) => {
        pub struct $cmd_name {
            aliases: Vec<&'static str>,
            clap: RefCell<App<'static, 'static>>,
            completers: Vec<&'static dyn Fn(&str, &Env) -> Vec<RustlinePair>>,
            named_completers: HashMap<String, fn(&str, &Env) -> Vec<RustlinePair>>,
        }

        impl $cmd_name {
            pub fn new() -> $cmd_name {
                lazy_static! {
                    static ref ALIASES_STR: String =
                        format!("{}:\n    {:?}", Yellow.paint("ALIASES"), $aliases);
                }
                let clap = start_clap($name, $about, &ALIASES_STR, $trailing_var_arg);
                let extra = $extra_args(clap);
                $cmd_name {
                    aliases: $aliases,
                    clap: RefCell::new(extra),
                    completers: $cmplters,
                    named_completers: $named_cmplters,
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
                    clickwriteln!(writer, "Couldn't print help: {}", res);
                }
                // clap print_help doesn't add final newline
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

            fn try_completed_named(
                &self,
                index: usize,
                opt: &str,
                prefix: &str,
                env: &Env,
            ) -> Vec<RustlinePair> {
                let parser = &self.clap.borrow().p;
                let opt_builder = parser.opts.iter().find(|opt_builder| {
                    let long_matched = match opt_builder.s.long {
                        Some(lstr) => lstr == &opt[2..], // strip off -- prefix we get passed
                        None => false,
                    };
                    long_matched
                        || (opt.len() == 2
                            && match opt_builder.s.short {
                                Some(schr) => schr == opt.chars().nth(1).unwrap(), // strip off - prefix we get passed
                                None => false,
                            })
                });
                match opt_builder {
                    Some(ob) => match self.named_completers.get(ob.s.long.unwrap_or_else(|| "")) {
                        Some(completer) => completer(prefix, env),
                        None => vec![],
                    },
                    None => self.try_complete(index, prefix, env),
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
                    .filter(|flag_builder| completer::long_matches(&flag_builder.s.long, prefix))
                    .map(|flag_builder| RustlinePair {
                        display: format!("--{}", flag_builder.s.long.unwrap()),
                        replacement: format!(
                            "{} ",
                            flag_builder.s.long.unwrap()[repoff..].to_string()
                        ),
                    });

                let opts = parser
                    .opts
                    .iter()
                    .filter(|opt_builder| completer::long_matches(&opt_builder.s.long, prefix))
                    .map(|opt_builder| RustlinePair {
                        display: format!("--{}", opt_builder.s.long.unwrap()),
                        replacement: format!(
                            "{} ",
                            opt_builder.s.long.unwrap()[repoff..].to_string()
                        ),
                    });

                flags.chain(opts).collect()
            }
        }
    };
}

// /// a clap validator for u32
// fn valid_u32(s: String) -> Result<(), String> {
//     s.parse::<u32>().map(|_| ()).map_err(|e| e.to_string())
// }

// /// a clap validator for duration
// fn valid_duration(s: String) -> Result<(), String> {
//     parse_duration(s.as_str())
//         .map(|_| ())
//         .map_err(|e| e.to_string())
// }

// /// a clap validator for rfc3339 dates
// fn valid_date(s: String) -> Result<(), String> {
//     DateTime::parse_from_rfc3339(s.as_str())
//         .map(|_| ())
//         .map_err(|e| e.to_string())
// }

// /// a clap validator for boolean
// fn valid_bool(s: String) -> Result<(), String> {
//     s.parse::<bool>().map(|_| ()).map_err(|e| e.to_string())
// }

// /// check if a pod has a waiting container
// fn has_waiting(pod: &Pod) -> bool {
//     if let Some(ref stats) = pod.status.container_statuses {
//         stats
//             .iter()
//             .any(|cs| matches!(cs.state, ContainerState::Waiting { .. }))
//     } else {
//         false
//     }
// }

// // Figure out the right thing to print for the phase of the given pod
// fn phase_str<'a>(pod: &Pod) -> Cow<'a, str> {
//     if pod.metadata.deletion_timestamp.is_some() {
//         // Was deleted
//         "Terminating".into()
//     } else if has_waiting(pod) {
//         "ContainerCreating".into()
//     } else {
//         pod.status.phase.clone().into()
//     }
// }

// get the number of ready containers and total containers
// or None if that cannot be determined
// fn ready_counts(pod: &Pod) -> Option<(u32, u32)> {
//     pod.status.container_statuses.as_ref().map(|statuses| {
//         let mut count = 0;
//         let mut ready = 0;
//         for stat in statuses.iter() {
//             count += 1;
//             if stat.ready {
//                 ready += 1;
//             }
//         }
//         (ready, count)
//     })
// }

// fn phase_style(phase: &str) -> &'static str {
//     phase_style_str(phase)
// }

// fn phase_style_str(phase: &str) -> &'static str {
//     match phase {
//         "Pending" | "Running" | "Active" => "Fg",
//         "Terminated" | "Terminating" => "Fr",
//         "ContainerCreating" => "Fy",
//         "Succeeded" => "Fb",
//         "Failed" => "Fr",
//         "Unknown" => "Fr",
//         _ => "Fr",
//     }
// }

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

// fn create_podlist_specs<'a>(
//     pod: Pod,
//     show_labels: bool,
//     show_annot: bool,
//     show_node: bool,
//     show_namespace: bool,
// ) -> (Pod, Vec<CellSpec<'a>>) {
//     let mut specs = vec![CellSpec::new_index(), pod.metadata.name.clone().into()];

//     let ready_str = match ready_counts(&pod) {
//         Some((ready, count)) => Cow::Owned(format!("{}/{}", ready, count)),
//         None => Cow::Borrowed("Unknown"),
//     };
//     specs.push(ready_str.into());

//     {
//         let ps = phase_str(&pod);
//         let ss = phase_style(&ps);
//         specs.push(CellSpec::with_style(ps.into(), ss));
//     }

//     if let Some(ts) = pod.metadata.creation_timestamp {
//         specs.push(time_since(ts).into());
//     } else {
//         specs.push("unknown".into());
//     }

//     let restarts = pod
//         .status
//         .container_statuses
//         .as_ref()
//         .map(|stats| stats.iter().fold(0, |acc, x| acc + x.restart_count))
//         .unwrap_or(0);
//     specs.push(restarts.to_string().into());

//     if show_labels {
//         specs.push(keyval_string(&pod.metadata.labels).into());
//     }

//     if show_annot {
//         specs.push(keyval_string(&pod.metadata.annotations).into());
//     }

//     if show_node {
//         specs.push(match pod.spec.node_name {
//             Some(ref nn) => nn.clone().into(),
//             None => "[Unknown]".into(),
//         });
//     }

//     if show_namespace {
//         specs.push(match pod.metadata.namespace {
//             Some(ref ns) => ns.clone().into(),
//             None => "[Unknown]".into(),
//         });
//     }
//     (pod, specs)
// }

// /// Print out the specified list of pods in a pretty format
// #[allow(clippy::too_many_arguments)]
// fn print_podlist(
//     mut podlist: PodList,
//     show_labels: bool,
//     show_annot: bool,
//     show_node: bool,
//     show_namespace: bool,
//     regex: Option<Regex>,
//     sort: Option<&str>,
//     reverse: bool,
//     writer: &mut ClickWriter,
// ) -> PodList {
//     let mut table = Table::new();
//     let mut title_row = row!["####", "Name", "Ready", "Phase", "Age", "Restarts"];

//     let show_labels = show_labels
//         || sort
//             .map(|s| s == "Lables" || s == "labels")
//             .unwrap_or(false);
//     let show_annot = show_annot
//         || sort
//             .map(|s| s == "Annotations" || s == "annotations")
//             .unwrap_or(false);
//     let show_node = show_node || sort.map(|s| s == "Node" || s == "node").unwrap_or(false);
//     let show_namespace = show_namespace
//         || sort
//             .map(|s| s == "Namespace" || s == "namespace")
//             .unwrap_or(false);

//     if show_labels {
//         title_row.add_cell(Cell::new("Labels"));
//     }
//     if show_annot {
//         title_row.add_cell(Cell::new("Annotations"));
//     }
//     if show_node {
//         title_row.add_cell(Cell::new("Node"));
//     }
//     if show_namespace {
//         title_row.add_cell(Cell::new("Namespace"));
//     }
//     table.set_titles(title_row);

//     if let Some(sortcol) = sort {
//         match sortcol {
//             "Name" | "name" => podlist
//                 .items
//                 .sort_by(|p1, p2| p1.metadata.name.partial_cmp(&p2.metadata.name).unwrap()),
//             "Ready" | "ready" => podlist.items.sort_by(|p1, p2| {
//                 opt_sort(ready_counts(p1), ready_counts(p2), |(r1, c1), (r2, c2)| {
//                     if c1 < c2 {
//                         cmp::Ordering::Less
//                     } else if c1 > c2 {
//                         cmp::Ordering::Greater
//                     } else if r1 < r2 {
//                         cmp::Ordering::Less
//                     } else if r1 > r2 {
//                         cmp::Ordering::Greater
//                     } else {
//                         cmp::Ordering::Equal
//                     }
//                 })
//             }),
//             "Age" | "age" => podlist.items.sort_by(|p1, p2| {
//                 opt_sort(
//                     p1.metadata.creation_timestamp,
//                     p2.metadata.creation_timestamp,
//                     |a1, a2| a1.partial_cmp(a2).unwrap(),
//                 )
//             }),
//             "Phase" | "phase" => podlist.items.sort_by_key(|phase| phase_str(phase)),
//             "Restarts" | "restarts" => podlist.items.sort_by(|p1, p2| {
//                 let p1r = p1
//                     .status
//                     .container_statuses
//                     .as_ref()
//                     .map(|stats| stats.iter().fold(0, |acc, x| acc + x.restart_count))
//                     .unwrap_or(0);
//                 let p2r = p2
//                     .status
//                     .container_statuses
//                     .as_ref()
//                     .map(|stats| stats.iter().fold(0, |acc, x| acc + x.restart_count))
//                     .unwrap_or(0);
//                 p1r.partial_cmp(&p2r).unwrap()
//             }),
//             "Labels" | "labels" => podlist.items.sort_by(|p1, p2| {
//                 let p1s = keyval_string(&p1.metadata.labels);
//                 let p2s = keyval_string(&p2.metadata.labels);
//                 p1s.partial_cmp(&p2s).unwrap()
//             }),
//             "Annotations" | "annotations" => podlist.items.sort_by(|p1, p2| {
//                 let p1s = keyval_string(&p1.metadata.annotations);
//                 let p2s = keyval_string(&p2.metadata.annotations);
//                 p1s.partial_cmp(&p2s).unwrap()
//             }),
//             "Node" | "node" => podlist.items.sort_by(|p1, p2| {
//                 opt_sort(
//                     p1.spec.node_name.as_ref(),
//                     p2.spec.node_name.as_ref(),
//                     |p1n, p2n| p1n.partial_cmp(p2n).unwrap(),
//                 )
//             }),
//             "Namespace" | "namespace" => podlist.items.sort_by(|p1, p2| {
//                 opt_sort(
//                     p1.metadata.namespace.as_ref(),
//                     p2.metadata.namespace.as_ref(),
//                     |p1n, p2n| p1n.partial_cmp(p2n).unwrap(),
//                 )
//             }),
//             _ => {
//                 clickwriteln!(
//                     writer,
//                     "Invalid sort col: {}, this is a bug, please report it",
//                     sortcol
//                 );
//             }
//         }
//     }

//     let to_map: Box<dyn Iterator<Item = Pod>> = if reverse {
//         Box::new(podlist.items.into_iter().rev())
//     } else {
//         Box::new(podlist.items.into_iter())
//     };

//     let pods_specs = to_map
//         .map(|pod| create_podlist_specs(pod, show_labels, show_annot, show_node, show_namespace));

//     let filtered = match regex {
//         Some(r) => crate::table::filter(pods_specs, r),
//         None => pods_specs.collect(),
//     };

//     crate::table::print_table(&mut table, &filtered, writer);

//     let final_pods = filtered.into_iter().map(|pod_spec| pod_spec.0).collect();
//     PodList { items: final_pods }
// }

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

// /// Print out the specified list of nodes in a pretty format
// fn print_nodelist(
//     mut nodelist: NodeList,
//     labels: bool,
//     regex: Option<Regex>,
//     sort: Option<&str>,
//     reverse: bool,
//     writer: &mut ClickWriter,
// ) -> NodeList {
//     let mut table = Table::new();
//     let mut title_row = row!["####", "Name", "State", "Age"];
//     let show_labels = labels
//         || sort
//             .map(|s| s == "Labels" || s == "labels")
//             .unwrap_or(false);
//     if show_labels {
//         title_row.add_cell(Cell::new("Labels"));
//     }
//     table.set_titles(title_row);

//     if let Some(sortcol) = sort {
//         match sortcol {
//             "Name" | "name" => nodelist
//                 .items
//                 .sort_by(|n1, n2| n1.metadata.name.partial_cmp(&n2.metadata.name).unwrap()),
//             "State" | "state" => nodelist.items.sort_by(|n1, n2| {
//                 let orn1 = n1.status.conditions.iter().find(|c| c.typ == "Ready");
//                 let orn2 = n2.status.conditions.iter().find(|c| c.typ == "Ready");
//                 opt_sort(orn1, orn2, |rn1, rn2| {
//                     let sort_key1 = if rn1.status == "True" {
//                         "Ready"
//                     } else {
//                         "Not Ready"
//                     };
//                     let sort_key2 = if rn2.status == "True" {
//                         "Ready"
//                     } else {
//                         "Not Ready"
//                     };
//                     sort_key1.partial_cmp(sort_key2).unwrap()
//                 })
//             }),
//             "Age" | "age" => nodelist.items.sort_by(|n1, n2| {
//                 opt_sort(
//                     n1.metadata.creation_timestamp,
//                     n2.metadata.creation_timestamp,
//                     |a1, a2| a1.partial_cmp(a2).unwrap(),
//                 )
//             }),
//             "Labels" | "labels" => nodelist.items.sort_by(|n1, n2| {
//                 let n1s = keyval_string(&n1.metadata.labels);
//                 let n2s = keyval_string(&n2.metadata.labels);
//                 n1s.partial_cmp(&n2s).unwrap()
//             }),
//             _ => {
//                 clickwriteln!(
//                     writer,
//                     "Invalid sort col: {}, this is a bug, please report it",
//                     sortcol
//                 );
//             }
//         }
//     }
//     let to_map: Box<dyn Iterator<Item = Node>> = if reverse {
//         Box::new(nodelist.items.into_iter().rev())
//     } else {
//         Box::new(nodelist.items.into_iter())
//     };

//     let nodes_specs = to_map.map(|node| {
//         let mut specs = Vec::new();
//         {
//             // scope borrows
//             let readycond: Option<&NodeCondition> =
//                 node.status.conditions.iter().find(|c| c.typ == "Ready");
//             let (state, state_style) = if let Some(cond) = readycond {
//                 if cond.status == "True" {
//                     ("Ready", "Fg")
//                 } else {
//                     ("Not Ready", "Fr")
//                 }
//             } else {
//                 ("Unknown", "Fy")
//             };

//             let state = if let Some(b) = node.spec.unschedulable {
//                 if b {
//                     format!("{}\nSchedulingDisabled", state)
//                 } else {
//                     state.to_owned()
//                 }
//             } else {
//                 state.to_owned()
//             };

//             specs.push(CellSpec::new_index());
//             specs.push(node.metadata.name.clone().into());
//             specs.push(CellSpec::with_style(state.into(), state_style));
//             specs.push(time_since(node.metadata.creation_timestamp.unwrap()).into());
//             if show_labels {
//                 specs.push(keyval_string(&node.metadata.labels).into());
//             }
//         }
//         (node, specs)
//     });

//     let filtered = match regex {
//         Some(r) => crate::table::filter(nodes_specs, r),
//         None => nodes_specs.collect(),
//     };

//     crate::table::print_table(&mut table, &filtered, writer);

//     let final_nodes = filtered.into_iter().map(|node_spec| node_spec.0).collect();
//     NodeList { items: final_nodes }
// }

// /// Print out the specified list of deployments in a pretty format
// fn print_deployments(
//     mut deplist: DeploymentList,
//     show_labels: bool,
//     regex: Option<Regex>,
//     sort: Option<&str>,
//     reverse: bool,
//     writer: &mut ClickWriter,
// ) -> DeploymentList {
//     let mut table = Table::new();
//     let mut title_row = row![
//         "####",
//         "Name",
//         "Desired",
//         "Current",
//         "Up To Date",
//         "Available",
//         "Age"
//     ];
//     let show_labels = show_labels
//         || sort
//             .map(|s| s == "Labels" || s == "labels")
//             .unwrap_or(false);
//     if show_labels {
//         title_row.add_cell(Cell::new("Labels"));
//     }
//     table.set_titles(title_row);

//     if let Some(sortcol) = sort {
//         match sortcol {
//             "Name" | "name" => deplist
//                 .items
//                 .sort_by(|d1, d2| d1.metadata.name.partial_cmp(&d2.metadata.name).unwrap()),
//             "Desired" | "desired" => deplist
//                 .items
//                 .sort_by(|d1, d2| d1.spec.replicas.partial_cmp(&d2.spec.replicas).unwrap()),
//             "Current" | "current" => deplist
//                 .items
//                 .sort_by(|d1, d2| d1.status.replicas.partial_cmp(&d2.status.replicas).unwrap()),
//             "UpToDate" | "uptodate" => deplist
//                 .items
//                 .sort_by(|d1, d2| d1.status.updated.partial_cmp(&d2.status.updated).unwrap()),
//             "Available" | "available" => deplist.items.sort_by(|d1, d2| {
//                 d1.status
//                     .available
//                     .partial_cmp(&d2.status.available)
//                     .unwrap()
//             }),
//             "Age" | "age" => deplist.items.sort_by(|p1, p2| {
//                 opt_sort(
//                     p1.metadata.creation_timestamp,
//                     p2.metadata.creation_timestamp,
//                     |a1, a2| a1.partial_cmp(a2).unwrap(),
//                 )
//             }),
//             "Labels" | "labels" => deplist.items.sort_by(|p1, p2| {
//                 let p1s = keyval_string(&p1.metadata.labels);
//                 let p2s = keyval_string(&p2.metadata.labels);
//                 p1s.partial_cmp(&p2s).unwrap()
//             }),
//             _ => {
//                 clickwriteln!(
//                     writer,
//                     "Invalid sort col: {}, this is a bug, please report it",
//                     sortcol
//                 );
//             }
//         }
//     }

//     let to_map: Box<dyn Iterator<Item = Deployment>> = if reverse {
//         Box::new(deplist.items.into_iter().rev())
//     } else {
//         Box::new(deplist.items.into_iter())
//     };

//     let deps_specs = to_map.map(|dep| {
//         let mut specs = Vec::new();
//         specs.push(CellSpec::new_index());
//         specs.push(dep.metadata.name.clone().into());
//         specs.push(CellSpec::with_align(
//             format!("{}", dep.spec.replicas).into(),
//             format::Alignment::CENTER,
//         ));
//         specs.push(CellSpec::with_align(
//             format!("{}", dep.status.replicas).into(),
//             format::Alignment::CENTER,
//         ));
//         specs.push(CellSpec::with_align(
//             format!("{}", dep.status.updated).into(),
//             format::Alignment::CENTER,
//         ));
//         specs.push(CellSpec::with_align(
//             format!("{}", dep.status.available).into(),
//             format::Alignment::CENTER,
//         ));
//         specs.push(time_since(dep.metadata.creation_timestamp.unwrap()).into());
//         if show_labels {
//             specs.push(keyval_string(&dep.metadata.labels).into());
//         }
//         (dep, specs)
//     });

//     let filtered = match regex {
//         Some(r) => crate::table::filter(deps_specs, r),
//         None => deps_specs.collect(),
//     };

//     crate::table::print_table(&mut table, &filtered, writer);

//     let final_deps = filtered.into_iter().map(|dep_spec| dep_spec.0).collect();
//     DeploymentList { items: final_deps }
// }

// service utility functions
fn get_external_ip<'a>(service: &Service) -> Cow<'a, str> {
    if let Some(ref eips) = service.spec.external_ips {
        shorten_to(eips.join(", "), 18).into()
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
                shorten_to(s, 18).into()
            } else {
                "<none>".into()
            }
        } else {
            "<none>".into()
        }
    }
}

fn get_ports<'a>(service: &Service) -> Cow<'a, str> {
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
    port_strs.join(",").into()
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

    let extipsandports: Vec<(Cow<'_, str>, Cow<'_, str>)> = servlist
        .items
        .iter()
        .map(|s| (get_external_ip(s), get_ports(s)))
        .collect();

    type ServiceAndPorts<'a> = (Service, (Cow<'a, str>, Cow<'a, str>));
    let mut servswithipportss: Vec<ServiceAndPorts<'_>> =
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
                clickwriteln!(
                    writer,
                    "Invalid sort col: {}, this is a bug, please report it",
                    sortcol
                );
            }
        }
    }

    let to_map: Box<dyn Iterator<Item = ServiceAndPorts<'_>>> = if reverse {
        Box::new(servswithipportss.into_iter().rev())
    } else {
        Box::new(servswithipportss.into_iter())
    };

    let service_specs = to_map.map(|(service, eipp)| {
        let mut specs = vec![
            CellSpec::new_index(),
            service.metadata.name.clone().into(),
            service
                .spec
                .cluster_ip
                .as_ref()
                .unwrap_or(&"<none>".to_owned())
                .to_string()
                .into(),
            eipp.0.into(),
            eipp.1.into(),
            time_since(service.metadata.creation_timestamp.unwrap()).into(),
        ];

        if show_labels {
            specs.push(keyval_string(&service.metadata.labels).into());
        }

        if show_namespace {
            specs.push(match service.metadata.namespace {
                Some(ref ns) => ns.clone().into(),
                None => "[Unknown]".into(),
            });
        }

        (service, specs)
    });

    let filtered = match regex {
        Some(r) => crate::table::filter(service_specs, r),
        None => service_specs.collect(),
    };

    crate::table::print_table(&mut table, &filtered, writer);

    let final_services = filtered
        .into_iter()
        .map(|service_spec| service_spec.0)
        .collect();
    ServiceList {
        items: final_services,
    }
}

// /// Print out the specified list of deployments in a pretty format
// fn print_namespaces(nslist: &NamespaceList, regex: Option<Regex>, writer: &mut ClickWriter) {
//     let mut table = Table::new();
//     table.set_titles(row!["Name", "Status", "Age"]);

//     let ns_specs = nslist.items.iter().map(|ns| {
//         let mut specs = vec![ns.metadata.name.as_str().into()];
//         let ps = ns.status.phase.as_str();
//         specs.push(CellSpec::with_style(ps.into(), phase_style_str(ps)));
//         specs.push(time_since(ns.metadata.creation_timestamp.unwrap()).into());
//         (ns, specs)
//     });

//     let filtered = match regex {
//         Some(r) => crate::table::filter(ns_specs, r),
//         None => ns_specs.collect(),
//     };

//     crate::table::print_table(&mut table, &filtered, writer);
// }

// Command defintions below.  See documentation for the command! macro for an explanation of
// arguments passed here

// command!(
//     Quit,
//     "quit",
//     "Quit click",
//     identity,
//     vec!["q", "quit", "exit"],
//     noop_complete!(),
//     no_named_complete!(),
//     |_, env, _| {
//         env.quit = true;
//     }
// );

// command!(
//     Pods,
//     "pods",
//     "Get pods (in current namespace if set)",
//     |clap: App<'static, 'static>| clap
//         .arg(
//             Arg::with_name("label")
//                 .short("l")
//                 .long("label")
//                 .help("Get pods with specified label selector (example: app=kinesis2prom)")
//                 .takes_value(true)
//         )
//         .arg(
//             Arg::with_name("regex")
//                 .short("r")
//                 .long("regex")
//                 .help("Filter pods by the specified regex")
//                 .takes_value(true)
//         )
//         .arg(
//             Arg::with_name("showlabels")
//                 .short("L")
//                 .long("labels")
//                 .help("Show pod labels as column in output")
//                 .takes_value(false)
//         )
//         .arg(
//             Arg::with_name("showannot")
//                 .short("A")
//                 .long("show-annotations")
//                 .help("Show pod annotations as column in output")
//                 .takes_value(false)
//         )
//         .arg(
//             Arg::with_name("shownode")
//                 .short("n")
//                 .long("show-node")
//                 .help("Show node pod is on as column in output")
//                 .takes_value(false)
//         )
//         .arg(
//             Arg::with_name("sort")
//                 .short("s")
//                 .long("sort")
//                 .help(
//                     "Sort by specified column (if column isn't shown by default, it will \
//                      be shown)"
//                 )
//                 .takes_value(true)
//                 .possible_values(&[
//                     "Name",
//                     "name",
//                     "Ready",
//                     "ready",
//                     "Phase",
//                     "phase",
//                     "Age",
//                     "age",
//                     "Restarts",
//                     "restarts",
//                     "Labels",
//                     "labels",
//                     "Annotations",
//                     "annotations",
//                     "Node",
//                     "node",
//                     "Namespace",
//                     "namespace"
//                 ])
//         )
//         .arg(
//             Arg::with_name("reverse")
//                 .short("R")
//                 .long("reverse")
//                 .help("Reverse the order of the returned list")
//                 .takes_value(false)
//         ),
//     vec!["pods"],
//     noop_complete!(),
//     IntoIter::new([(
//         "sort".to_string(),
//         completer::pod_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
//     )])
//     .collect(),
//     |matches, env, writer| {
//         let regex = match crate::table::get_regex(&matches) {
//             Ok(r) => r,
//             Err(s) => {
//                 writeln!(stderr(), "{}", s).unwrap_or(());
//                 return;
//             }
//         };

//         let mut urlstr = if let Some(ref ns) = env.namespace {
//             format!("/api/v1/namespaces/{}/pods", ns)
//         } else {
//             "/api/v1/pods".to_owned()
//         };

//         let mut pushed_label = false;
//         if let Some(label_selector) = matches.value_of("label") {
//             urlstr.push_str("?labelSelector=");
//             urlstr.push_str(label_selector);
//             pushed_label = true;
//         }

//         if let ObjectSelection::Single(obj) = env.current_selection() {
//             if obj.is(ObjType::Node) {
//                 if pushed_label {
//                     urlstr.push('&');
//                 } else {
//                     urlstr.push('?');
//                 }
//                 urlstr.push_str("fieldSelector=spec.nodeName=");
//                 urlstr.push_str(obj.name());
//             }
//         }

//         let pl: Option<PodList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));

//         match pl {
//             Some(l) => {
//                 let end_list = print_podlist(
//                     l,
//                     matches.is_present("showlabels"),
//                     matches.is_present("showannot"),
//                     matches.is_present("shownode"),
//                     env.namespace.is_none(),
//                     regex,
//                     matches.value_of("sort"),
//                     matches.is_present("reverse"),
//                     writer,
//                 );
//                 env.set_last_objs(end_list);
//             }
//             None => env.clear_last_objs(),
//         }
//     }
// );

// fn delete_obj(env: &Env, obj: &KObj, delete_body: &str, writer: &mut ClickWriter) {
//     let name = obj.name();
//     let namespace = match obj.typ {
//         ObjType::Node => "",
//         _ => match obj.namespace {
//             Some(ref ns) => ns,
//             None => {
//                 clickwriteln!(writer, "Don't know namespace for {}", obj.name());
//                 return;
//             }
//         },
//     };
//     clickwrite!(writer, "Delete {} {} [y/N]? ", obj.type_str(), name);
//     io::stdout().flush().expect("Could not flush stdout");
//     let mut conf = String::new();
//     if io::stdin().read_line(&mut conf).is_ok() {
//         if conf.trim() == "y" || conf.trim() == "yes" {
//             let url = obj.url(namespace);
//             let body = if obj.is(ObjType::Service) {
//                 None
//             } else {
//                 Some(delete_body)
//             };
//             let result = env.run_on_kluster(|k| k.delete(url.as_str(), body, true));
//             if let Some(x) = result {
//                 if x.status.is_success() {
//                     clickwriteln!(writer, "Deleted");
//                 } else {
//                     clickwriteln!(writer, "Failed to delete: {:?}", x.get_ref());
//                 }
//             } else {
//                 clickwriteln!(writer, "Failed to delete");
//             }
//         } else {
//             clickwriteln!(writer, "Not deleting");
//         }
//     } else {
//         writeln!(stderr(), "Could not read response, not deleting.").unwrap_or(());
//     }
// }

// command!(
//     Delete,
//     "delete",
//     "Delete the active object (will ask for confirmation)",
//     |clap: App<'static, 'static>| {
//         clap.arg(
//         Arg::with_name("grace")
//             .short("g")
//             .long("gracePeriod")
//             .help("The duration in seconds before the object should be deleted.")
//             .validator(valid_u32)
//             .takes_value(true)
//     ).arg(Arg::with_name("cascade")
//             .short("c")
//             .long("cascade")
//             .help("If true (the default), dependant objects are deleted. \
//                    If false, they are orphaned")
//             .validator(valid_bool)
//             .takes_value(true)
//     ).arg(Arg::with_name("now")
//           .long("now")
//           .help("If set, resources are signaled for immediate shutdown (same as --grace-period=1)")
//           .takes_value(false)
//           .conflicts_with("grace")
//     ).arg(Arg::with_name("force")
//           .long("force")
//           .help("Force immediate deletion.  For some resources this may result in inconsistency or \
//                  data loss")
//           .takes_value(false)
//           .conflicts_with("grace")
//           .conflicts_with("now")
//     )
//     },
//     vec!["delete"],
//     noop_complete!(),
//     no_named_complete!(),
//     |matches, env, writer| {
//         let mut policy = "Foreground";
//         if let Some(cascade) = matches.value_of("cascade") {
//             if !(cascade.parse::<bool>()).unwrap() {
//                 // safe as validated
//                 policy = "Orphan";
//             }
//         }
//         let mut delete_body = json!({
//             "kind":"DeleteOptions",
//             "apiVersion":"v1",
//             "propagationPolicy": policy
//         });
//         if let Some(grace) = matches.value_of("grace") {
//             let graceu32 = grace.parse::<u32>().unwrap(); // safe as validated
//             if graceu32 == 0 {
//                 // don't allow zero, make it one.  zero is force delete which
//                 // can mess things up.
//                 delete_body
//                     .as_object_mut()
//                     .unwrap()
//                     .insert("gracePeriodSeconds".to_owned(), json!(1));
//             } else {
//                 // already validated that it's a legit number
//                 delete_body
//                     .as_object_mut()
//                     .unwrap()
//                     .insert("gracePeriodSeconds".to_owned(), json!(graceu32));
//             }
//         } else if matches.is_present("force") {
//             delete_body
//                 .as_object_mut()
//                 .unwrap()
//                 .insert("gracePeriodSeconds".to_owned(), json!(0));
//         } else if matches.is_present("now") {
//             delete_body
//                 .as_object_mut()
//                 .unwrap()
//                 .insert("gracePeriodSeconds".to_owned(), json!(1));
//         }
//         let delete_body = delete_body.to_string();

//         env.apply_to_selection(
//             writer,
//             Some(&env.click_config.range_separator),
//             |obj, writer| {
//                 delete_obj(env, obj, &delete_body, writer);
//             },
//         );
//     }
// );

// fn containers_string(pod: &Pod) -> String {
//     let mut buf = String::new();
//     if let Some(ref stats) = pod.status.container_statuses {
//         for cont in stats.iter() {
//             buf.push_str(format!("Name:\t{}\n", cont.name).as_str());
//             buf.push_str(format!("  Image:\t{}\n", cont.image).as_str());
//             buf.push_str(format!("  State:\t{}\n", cont.state).as_str());
//             buf.push_str(format!("  Ready:\t{}\n", cont.ready).as_str());

//             // find the spec for this container
//             let mut spec_it = pod.spec.containers.iter().filter(|cs| cs.name == cont.name);
//             if let Some(spec) = spec_it.next() {
//                 if let Some(ref vols) = spec.volume_mounts {
//                     buf.push_str("  Volumes:\n");
//                     for vol in vols.iter() {
//                         buf.push_str(format!("   {}\n", vol.name).as_str());
//                         buf.push_str(format!("    Path:\t{}\n", vol.mount_path).as_str());
//                         buf.push_str(
//                             format!(
//                                 "    Sub-Path:\t{}\n",
//                                 vol.sub_path.as_ref().unwrap_or(&"".to_owned())
//                             )
//                             .as_str(),
//                         );
//                         buf.push_str(
//                             format!("    Read-Only:\t{}\n", vol.read_only.unwrap_or(false))
//                                 .as_str(),
//                         );
//                     }
//                 } else {
//                     buf.push_str("  No Volumes\n");
//                 }
//             }
//             buf.push('\n');
//         }
//     } else {
//         buf.push_str("<No Containers>\n");
//     }
//     buf
// }

// // conainer helper command
// fn print_containers(obj: &KObj, env: &Env, writer: &mut ClickWriter) {
//     let url = format!(
//         "/api/v1/namespaces/{}/pods/{}",
//         obj.namespace.as_ref().unwrap(),
//         obj.name()
//     );
//     let pod_opt: Option<Pod> = env.run_on_kluster(|k| k.get(url.as_str()));
//     if let Some(pod) = pod_opt {
//         clickwrite!(writer, "{}", containers_string(&pod)); // extra newline in returned string
//     }
// }

// command!(
//     Containers,
//     "containers",
//     "List containers on the active pod",
//     identity,
//     vec!["conts", "containers"],
//     noop_complete!(),
//     no_named_complete!(),
//     |_matches, env, writer| {
//         env.apply_to_selection(
//             writer,
//             Some(&env.click_config.range_separator),
//             |obj, writer| {
//                 if obj.is_pod() {
//                     print_containers(obj, env, writer);
//                 } else {
//                     clickwriteln!(writer, "containers only possible on a Pod");
//                 }
//             },
//         );
//     }
// );

// command!(
//     Nodes,
//     "nodes",
//     "Get nodes",
//     |clap: App<'static, 'static>| clap
//         .arg(
//             Arg::with_name("labels")
//                 .short("L")
//                 .long("labels")
//                 .help("include labels in output")
//                 .takes_value(false)
//         )
//         .arg(
//             Arg::with_name("regex")
//                 .short("r")
//                 .long("regex")
//                 .help("Filter pods by the specified regex")
//                 .takes_value(true)
//         )
//         .arg(
//             Arg::with_name("sort")
//                 .short("s")
//                 .long("sort")
//                 .help(
//                     "Sort by specified column (if column isn't shown by default, it will \
//                      be shown)"
//                 )
//                 .takes_value(true)
//                 .possible_values(&[
//                     "Name", "name", "State", "state", "Age", "age", "Labels", "labels",
//                 ])
//         )
//         .arg(
//             Arg::with_name("reverse")
//                 .short("R")
//                 .long("reverse")
//                 .help("Reverse the order of the returned list")
//                 .takes_value(false)
//         ),
//     vec!["nodes"],
//     noop_complete!(),
//     IntoIter::new([(
//         "sort".to_string(),
//         completer::node_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
//     )])
//     .collect(),
//     |matches, env, writer| {
//         let regex = match crate::table::get_regex(&matches) {
//             Ok(r) => r,
//             Err(s) => {
//                 write!(stderr(), "{}\n", s).unwrap_or(());
//                 return;
//             }
//         };

//         let url = "/api/v1/nodes";
//         let nl: Option<NodeList> = env.run_on_kluster(|k| k.get(url));
//         match nl {
//             Some(n) => {
//                 let final_list = print_nodelist(
//                     n,
//                     matches.is_present("labels"),
//                     regex,
//                     matches.value_of("sort"),
//                     matches.is_present("reverse"),
//                     writer,
//                 );
//                 env.set_last_objs(final_list);
//             }
//             None => env.clear_last_objs(),
//         }
//     }
// );

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
    IntoIter::new([(
        "sort".to_string(),
        completer::service_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
    )])
    .collect(),
    |matches, env, writer| {
        let regex = match crate::table::get_regex(&matches) {
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
            env.set_last_objs(filtered);
        } else {
            clickwriteln!(writer, "no services");
            env.clear_last_objs();
        }
    }
);

// command!(
//     Deployments,
//     "deployments",
//     "Get deployments (in current namespace if set)",
//     |clap: App<'static, 'static>| clap
//         .arg(
//             Arg::with_name("label")
//                 .short("l")
//                 .long("label")
//                 .help("Get deployments with specified label selector")
//                 .takes_value(true)
//         )
//         .arg(
//             Arg::with_name("regex")
//                 .short("r")
//                 .long("regex")
//                 .help("Filter deployments by the specified regex")
//                 .takes_value(true)
//         )
//         .arg(
//             Arg::with_name("showlabels")
//                 .short("L")
//                 .long("labels")
//                 .help("Show labels as column in output")
//                 .takes_value(false)
//         )
//         .arg(
//             Arg::with_name("sort")
//                 .short("s")
//                 .long("sort")
//                 .help(
//                     "Sort by specified column (if column isn't shown by default, it will \
//                      be shown)"
//                 )
//                 .takes_value(true)
//                 .possible_values(&[
//                     "Name",
//                     "name",
//                     "Desired",
//                     "desired",
//                     "Current",
//                     "current",
//                     "UpToDate",
//                     "uptodate",
//                     "Available",
//                     "available",
//                     "Age",
//                     "age",
//                     "Labels",
//                     "labels"
//                 ])
//         )
//         .arg(
//             Arg::with_name("reverse")
//                 .short("R")
//                 .long("reverse")
//                 .help("Reverse the order of the returned list")
//                 .takes_value(false)
//         ),
//     vec!["deps", "deployments"],
//     noop_complete!(),
//     IntoIter::new([(
//         "sort".to_string(),
//         completer::deployment_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
//     )])
//     .collect(),
//     |matches, env, writer| {
//         let regex = match crate::table::get_regex(&matches) {
//             Ok(r) => r,
//             Err(s) => {
//                 write!(stderr(), "{}\n", s).unwrap_or(());
//                 return;
//             }
//         };

//         let mut urlstr = if let Some(ref ns) = env.namespace {
//             format!("/apis/extensions/v1beta1/namespaces/{}/deployments", ns)
//         } else {
//             "/apis/extensions/v1beta1/deployments".to_owned()
//         };

//         if let Some(label_selector) = matches.value_of("label") {
//             urlstr.push_str("?labelSelector=");
//             urlstr.push_str(label_selector);
//         }

//         let dl: Option<DeploymentList> = env.run_on_kluster(|k| k.get(urlstr.as_str()));
//         match dl {
//             Some(d) => {
//                 let final_list = print_deployments(
//                     d,
//                     matches.is_present("showlabels"),
//                     regex,
//                     matches.value_of("sort"),
//                     matches.is_present("reverse"),
//                     writer,
//                 );
//                 env.set_last_objs(final_list);
//             }
//             None => env.clear_last_objs(),
//         }
//     }
// );
