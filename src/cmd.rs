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

//use crate::completer;
use crate::env::Env;

//use crate::kube::{Service, ServiceList};
use crate::output::ClickWriter;

//use ansi_term::Colour::Yellow;

//use chrono::offset::Utc;
//use chrono::DateTime;
use clap::{App, AppSettings, ArgMatches};
//use humantime::parse_duration;

//use prettytable::Cell;
use prettytable::format;
//use regex::Regex;
use rustyline::completion::Pair as RustlinePair;
//use serde_json::Value;

//use std::array::IntoIter;
//use std::borrow::Cow;
use std::cell::RefCell;
//use std::collections::HashMap;
use std::io::Write;
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

// fn time_since(date: DateTime<Utc>) -> String {
//     let now = Utc::now();
//     let diff = now.signed_duration_since(date);
//     if diff.num_days() > 0 {
//         format!(
//             "{}d {}h",
//             diff.num_days(),
//             (diff.num_hours() - (24 * diff.num_days()))
//         )
//     } else if diff.num_hours() > 0 {
//         format!(
//             "{}h {}m",
//             diff.num_hours(),
//             (diff.num_minutes() - (60 * diff.num_hours()))
//         )
//     } else if diff.num_minutes() > 0 {
//         format!(
//             "{}m {}s",
//             diff.num_minutes(),
//             (diff.num_seconds() - (60 * diff.num_minutes()))
//         )
//     } else {
//         format!("{}s", diff.num_seconds())
//     }
// }

// if s is longer than max_len it will be shorted and have ... added to be max_len
// fn shorten_to(s: String, max_len: usize) -> String {
//     if s.len() > max_len {
//         format!("{}...", &s[0..(max_len - 3)])
//     } else {
//         s
//     }
// }

// Build a multi-line string of the specified
// fn keyval_string(keyvals: &Option<serde_json::Map<String, Value>>) -> String {
//     let mut buf = String::new();
//     if let Some(ref lbs) = keyvals {
//         for (key, val) in lbs.iter() {
//             buf.push_str(key);
//             buf.push('=');
//             if let Some(s) = val.as_str() {
//                 buf.push_str(s);
//             } else {
//                 buf.push_str(format!("{}", val).as_str());
//             }
//             buf.push('\n');
//         }
//     }
//     buf
// }

// // service utility functions
// fn get_external_ip<'a>(service: &Service) -> Cow<'a, str> {
//     if let Some(ref eips) = service.spec.external_ips {
//         shorten_to(eips.join(", "), 18).into()
//     } else {
//         // look in the status for the elb name
//         if let Some(ing_val) = service.status.pointer("/loadBalancer/ingress") {
//             if let Some(ing_arry) = ing_val.as_array() {
//                 let strs: Vec<&str> = ing_arry
//                     .iter()
//                     .map(|v| {
//                         if let Some(hv) = v.get("hostname") {
//                             hv.as_str().unwrap_or("")
//                         } else if let Some(ipv) = v.get("ip") {
//                             ipv.as_str().unwrap_or("")
//                         } else {
//                             ""
//                         }
//                     })
//                     .collect();
//                 let s = strs.join(", ");
//                 shorten_to(s, 18).into()
//             } else {
//                 "<none>".into()
//             }
//         } else {
//             "<none>".into()
//         }
//     }
// }

// fn get_ports<'a>(service: &Service) -> Cow<'a, str> {
//     let port_strs: Vec<String> = if let Some(ref ports) = service.spec.ports {
//         ports
//             .iter()
//             .map(|p| {
//                 if let Some(np) = p.node_port {
//                     format!("{}:{}/{}", p.port, np, p.protocol)
//                 } else {
//                     format!("{}/{}", p.port, p.protocol)
//                 }
//             })
//             .collect()
//     } else {
//         vec!["<none>".to_owned()]
//     };
//     port_strs.join(",").into()
// }

// /// Print out the specified list of services in a pretty format
// fn print_servicelist(
//     servlist: ServiceList,
//     regex: Option<Regex>,
//     show_labels: bool,
//     show_namespace: bool,
//     sort: Option<&str>,
//     reverse: bool,
//     writer: &mut ClickWriter,
// ) -> ServiceList {
//     let mut table = Table::new();
//     let mut title_row = row![
//         "####",
//         "Name",
//         "ClusterIP",
//         "External IPs",
//         "Port(s)",
//         "Age"
//     ];

//     let show_labels = show_labels
//         || sort
//             .map(|s| s == "Labels" || s == "labels")
//             .unwrap_or(false);
//     let show_namespace = show_namespace
//         || sort
//             .map(|s| s == "Namespace" || s == "namespace")
//             .unwrap_or(false);

//     if show_labels {
//         title_row.add_cell(Cell::new("Labels"));
//     }
//     if show_namespace {
//         title_row.add_cell(Cell::new("Namespace"));
//     }
//     table.set_titles(title_row);

//     let extipsandports: Vec<(Cow<'_, str>, Cow<'_, str>)> = servlist
//         .items
//         .iter()
//         .map(|s| (get_external_ip(s), get_ports(s)))
//         .collect();

//     type ServiceAndPorts<'a> = (Service, (Cow<'a, str>, Cow<'a, str>));
//     let mut servswithipportss: Vec<ServiceAndPorts<'_>> =
//         servlist.items.into_iter().zip(extipsandports).collect();

//     if let Some(sortcol) = sort {
//         match sortcol {
//             "Name" | "name" => servswithipportss
//                 .sort_by(|s1, s2| s1.0.metadata.name.partial_cmp(&s2.0.metadata.name).unwrap()),
//             "Age" | "age" => servswithipportss.sort_by(|s1, s2| {
//                 opt_sort(
//                     s1.0.metadata.creation_timestamp,
//                     s2.0.metadata.creation_timestamp,
//                     |a1, a2| a1.partial_cmp(a2).unwrap(),
//                 )
//             }),
//             "Labels" | "labels" => servswithipportss.sort_by(|s1, s2| {
//                 let s1s = keyval_string(&s1.0.metadata.labels);
//                 let s2s = keyval_string(&s2.0.metadata.labels);
//                 s1s.partial_cmp(&s2s).unwrap()
//             }),
//             "Namespace" | "namespace" => servswithipportss.sort_by(|s1, s2| {
//                 opt_sort(
//                     s1.0.metadata.namespace.as_ref(),
//                     s2.0.metadata.namespace.as_ref(),
//                     |s1n, s2n| s1n.partial_cmp(s2n).unwrap(),
//                 )
//             }),
//             "ClusterIP" | "clusterip" => servswithipportss.sort_by(|s1, s2| {
//                 opt_sort(
//                     s1.0.spec.cluster_ip.as_ref(),
//                     s2.0.spec.cluster_ip.as_ref(),
//                     |s1cip, s2cip| s1cip.partial_cmp(s2cip).unwrap(),
//                 )
//             }),
//             "ExternalIP" | "externalip" => {
//                 servswithipportss.sort_by(|s1, s2| (s1.1).0.partial_cmp(&(s2.1).0).unwrap())
//             }
//             "Ports" | "ports" => {
//                 servswithipportss.sort_by(|s1, s2| (s1.1).1.partial_cmp(&(s2.1).1).unwrap())
//             }
//             _ => {
//                 clickwriteln!(
//                     writer,
//                     "Invalid sort col: {}, this is a bug, please report it",
//                     sortcol
//                 );
//             }
//         }
//     }

//     let to_map: Box<dyn Iterator<Item = ServiceAndPorts<'_>>> = if reverse {
//         Box::new(servswithipportss.into_iter().rev())
//     } else {
//         Box::new(servswithipportss.into_iter())
//     };

//     let service_specs = to_map.map(|(service, eipp)| {
//         let mut specs = vec![
//             CellSpec::new_index(),
//             service.metadata.name.clone().into(),
//             service
//                 .spec
//                 .cluster_ip
//                 .as_ref()
//                 .unwrap_or(&"<none>".to_owned())
//                 .to_string()
//                 .into(),
//             eipp.0.into(),
//             eipp.1.into(),
//             time_since(service.metadata.creation_timestamp.unwrap()).into(),
//         ];

//         if show_labels {
//             specs.push(keyval_string(&service.metadata.labels).into());
//         }

//         if show_namespace {
//             specs.push(match service.metadata.namespace {
//                 Some(ref ns) => ns.clone().into(),
//                 None => "[Unknown]".into(),
//             });
//         }

//         (service, specs)
//     });

//     let filtered = match regex {
//         Some(r) => crate::table::filter(service_specs, r),
//         None => service_specs.collect(),
//     };

//     crate::table::print_table(&mut table, &filtered, writer);

//     let final_services = filtered
//         .into_iter()
//         .map(|service_spec| service_spec.0)
//         .collect();
//     ServiceList {
//         items: final_services,
//     }
// }

// command!(
//     Services,
//     "services",
//     "Get services (in current namespace if set)",
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
//                 .help("Filter services by the specified regex")
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
//                     "Name",
//                     "name",
//                     "ClusterIP",
//                     "clusterip",
//                     "ExternalIP",
//                     "externalip",
//                     "Age",
//                     "age",
//                     "Ports",
//                     "ports",
//                     "Labels",
//                     "labels",
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
//     vec!["services"],
//     noop_complete!(),
//     IntoIter::new([(
//         "sort".to_string(),
//         completer::service_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
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

//         let url = if let Some(ref ns) = env.namespace {
//             format!("/api/v1/namespaces/{}/services", ns)
//         } else {
//             "/api/v1/services".to_owned()
//         };
//         let sl: Option<ServiceList> = env.run_on_kluster(|k| k.get(url.as_str()));
//         if let Some(s) = sl {
//             let filtered = print_servicelist(
//                 s,
//                 regex,
//                 matches.is_present("labels"),
//                 env.namespace.is_none(),
//                 matches.value_of("sort"),
//                 matches.is_present("reverse"),
//                 writer,
//             );
//             env.set_last_objs(filtered);
//         } else {
//             clickwriteln!(writer, "no services");
//             env.clear_last_objs();
//         }
//     }
// );
