use chrono::offset::Utc;
use chrono::DateTime;
use clap::{Arg, ArgMatches};
use humantime::parse_duration;
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::ObjectMeta, http::Request, List, ListableResource, Metadata,
};
use prettytable::{Cell, Row};
use regex::Regex;
use rustyline::completion::Pair;
use serde::Deserialize;

use crate::env::Env;
use crate::kobj::KObj;
use crate::output::ClickWriter;
use crate::table::CellSpec;

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::io::{stderr, Write};

// utility types
type RowSpec<'a> = Vec<CellSpec<'a>>;
type Extractor<T> = fn(&T) -> Option<CellSpec<'_>>;

// command definition
/// Just return what we're given.  Useful for no-op closures in
/// command! macro invocation
fn identity<T>(t: T) -> T {
    t
}

/// a clap validator for u32
fn valid_u32(s: String) -> Result<(), String> {
    s.parse::<u32>().map(|_| ()).map_err(|e| e.to_string())
}

fn uppercase_first(s: &str) -> String {
    let mut cs = s.chars();
    match cs.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + cs.as_str(),
    }
}

pub fn try_complete_all(prefix: &str, cols: &[&str], extra_cols: &[&str]) -> Vec<Pair> {
    let mut v = vec![];
    for val in cols.iter().chain(extra_cols.iter()) {
        if let Some(rest) = val.strip_prefix(prefix) {
            v.push(Pair {
                display: val.to_string(),
                replacement: rest.to_string(),
            });
        }
    }
    v
}

pub fn try_complete(prefix: &str, extra_cols: &[&str]) -> Vec<Pair> {
    let mut v = vec![];
    for val in extra_cols.iter() {
        if let Some(rest) = val.strip_prefix(prefix) {
            v.push(Pair {
                display: val.to_string(),
                replacement: rest.to_string(),
            });
        }
    }
    v
}

macro_rules! extract_first {
    ($map: ident) => {{
        let mut result: [&str; $map.len()] = [""; $map.len()];
        let mut i = 0;
        while i < $map.len() {
            result[i] = $map[i].0;
            i += 1;
        }
        result
    }};
}

/// convenience macro for commands that list things (pods, nodes, statefulsets, etc). this macro
/// adds the common various sorting/showing arguments and completors and then calls the base command
/// macro
macro_rules! list_command {
    ($cmd_name:ident, $name:expr, $about:expr, $cols: expr, $extra_cols:expr, $extra_args:expr,
     $aliases:expr, $cmplters: expr, $named_cmplters: expr, $cmd_expr:expr) => {
        mod list_sort_completers {
            use crate::{command::try_complete_all, env::Env};
            use rustyline::completion::Pair;
            #[allow(non_snake_case)]
            pub fn $cmd_name(prefix: &str, _env: &Env) -> Vec<Pair> {
                try_complete_all(prefix, $cols, $extra_cols)
            }
        }

        mod list_show_completers {
            use crate::{command::try_complete, env::Env};
            use rustyline::completion::Pair;
            #[allow(non_snake_case)]
            pub fn $cmd_name(prefix: &str, _env: &Env) -> Vec<Pair> {
                try_complete(prefix, $extra_cols)
            }
        }

        use rustyline::completion::Pair;
        command!(
            $cmd_name,
            $name,
            $about,
            $extra_args,
            $aliases,
            $cmplters,
            //$named_cmplters,
            IntoIter::new([
                (
                    "sort".to_string(),
                    list_sort_completers::$cmd_name as fn(&str, &Env) -> Vec<Pair>
                ),
                (
                    "show".to_string(),
                    list_show_completers::$cmd_name as fn(&str, &Env) -> Vec<Pair>
                )
            ])
            .chain($named_cmplters)
            .collect(),
            $cmd_expr,
            false
        );
    };
}

// these have to come after the macro def since they use the above macro

pub mod alias; // commands for alias/unalias
pub mod click; // commands internal to click (setting config values, etc)
pub mod delete; // command to delete objects
pub mod deployments; // command to list deployments
pub mod events; // commands to print events
pub mod exec; // command to exec into pods
pub mod logs; // command to get pod logs
pub mod namespaces; // commands relating to namespaces
pub mod nodes; // commands relating to nodes
pub mod pods; //commands relating to pods
pub mod portforwards; // commands for forwarding ports
pub mod statefulsets; // commands for statefulsets
pub mod volumes; // commands relating to volumes

fn mapped_val(key: &str, map: &[(&'static str, &'static str)]) -> Option<&'static str> {
    for (map_key, val) in map.iter() {
        if &key == map_key {
            return Some(val);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)] // factoring this out into structs just makes it worse
pub fn run_list_command<T, F>(
    matches: ArgMatches,
    env: &mut Env,
    writer: &mut ClickWriter,
    mut cols: Vec<&str>,
    request: Request<Vec<u8>>,
    col_map: &[(&'static str, &'static str)],
    extra_col_map: Option<&[(&'static str, &'static str)]>,
    extractors: Option<&HashMap<String, Extractor<T>>>,
    get_kobj: F,
) where
    T: ListableResource + Metadata<Ty = ObjectMeta> + for<'de> Deserialize<'de> + Debug,
    F: Fn(&T) -> KObj,
{
    let regex = match crate::table::get_regex(&matches) {
        Ok(r) => r,
        Err(s) => {
            writeln!(stderr(), "{}", s).unwrap_or(());
            return;
        }
    };

    let list_opt: Option<List<T>> = env.run_on_context(|c| c.execute_list(request));

    let mut flags: Vec<&str> = match matches.values_of("show") {
        Some(v) => v.collect(),
        None => vec![],
    };

    let sort = matches
        .value_of("sort")
        .map(|s| match s.to_lowercase().as_str() {
            "age" => {
                let sf = crate::command::PreExtractSort {
                    cmp: crate::command::age_cmp,
                };
                SortFunc::Pre(sf)
            }
            other => {
                if let Some(col) = mapped_val(other, col_map) {
                    SortFunc::Post(col)
                } else if let Some(ecm) = extra_col_map {
                    let mut func = None;
                    for (flag, col) in ecm.iter() {
                        if flag.eq(&other) {
                            flags.push(flag);
                            func = Some(SortFunc::Post(col));
                        }
                    }
                    match func {
                        Some(f) => f,
                        None => panic!("Shouldn't be allowed to ask to sort by: {}", other),
                    }
                } else {
                    panic!("Shouldn't be allowed to ask to sort by: {}", other);
                }
            }
        });

    if let Some(ecm) = extra_col_map {
        // if we're not in a namespace, we want to add a namespace col if it's in extra_col_map
        if env.namespace.is_none() && mapped_val("namespace", ecm).is_some() {
            flags.push("namespace");
        }

        add_extra_cols(&mut cols, matches.is_present("labels"), flags, ecm);
    }

    handle_list_result(
        env,
        writer,
        cols,
        list_opt,
        extractors,
        regex,
        sort,
        matches.is_present("reverse"),
        get_kobj,
    );
}

// /// a clap validator for duration
fn valid_duration(s: String) -> Result<(), String> {
    parse_duration(s.as_str())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// /// a clap validator for rfc3339 dates
fn valid_date(s: String) -> Result<(), String> {
    DateTime::parse_from_rfc3339(s.as_str())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// /// a clap validator for boolean
// fn valid_bool(s: String) -> Result<(), String> {
//     s.parse::<bool>().map(|_| ()).map_err(|e| e.to_string())
// }

// table printing / building
/* this function abstracts the standard handling code for when a k8s call returns a list of objects.
 * it does the following thins:
 * - builds the row specs based on the passed extractors/regex
 * - gets the kobks from each listable object
 * -- sets the env to have the built list as its current list
 * -- clears the env list if the built list was empty
 *
 * NB: This function assumes you want the printed list to be numbered. It further assumes the cols
 * will NOT include a colume named ####, and inserts it for you at the start.
 */
#[allow(clippy::too_many_arguments)]
pub fn handle_list_result<'a, T, F>(
    env: &mut Env,
    writer: &mut ClickWriter,
    cols: Vec<&str>,
    list_opt: Option<List<T>>,
    extractors: Option<&HashMap<String, Extractor<T>>>,
    regex: Option<Regex>,
    sort: Option<SortFunc<T>>,
    reverse: bool,
    get_kobj: F,
) where
    T: 'a + ListableResource + Metadata<Ty = ObjectMeta>,
    F: Fn(&T) -> KObj,
{
    match list_opt {
        Some(mut list) => {
            if let Some(SortFunc::Pre(func)) = sort.as_ref() {
                list.items.sort_by(|a, b| (func.cmp)(a, b));
            }

            let mut specs = build_specs(&cols, &list, extractors, true, regex, get_kobj);

            let mut titles: Vec<Cell> = vec![Cell::new("####")];
            titles.reserve(cols.len());
            for col in cols.iter() {
                titles.push(Cell::new(col));
            }

            if let Some(SortFunc::Post(colname)) = sort {
                let index = cols.iter().position(|&c| c == colname);
                match index {
                    Some(index) => {
                        let idx = index + 1; // +1 for #### col
                        specs.sort_by(|a, b| a.1.get(idx).unwrap().cmp(b.1.get(idx).unwrap()));
                    }
                    None => clickwriteln!(
                        writer,
                        "Asked to sort by {}, but it's not a column in the output",
                        colname
                    ),
                }
            }

            let (kobjs, rows): (Vec<KObj>, Vec<RowSpec>) = if reverse {
                specs.into_iter().rev().unzip()
            } else {
                specs.into_iter().unzip()
            };

            crate::table::print_table_kapi(Row::new(titles), rows, writer);
            env.set_last_objs(kobjs);
        }
        None => env.clear_last_objs(),
    }
}

// row building

/* Build row specs and a kobj vec from data returned from k8s.
 *
 * cols is a list of names of columns to build. "Name" * and "Age" are handled, other names need to
 * be in 'extractors', and the extractor for the specified name will be used.
 *
 * include_index = true will put an index (numbered) column as the first item in the row
 *
 * regex: if this is Some(regex) then only rows that have some cell that matches the regex will be
 * included in the output
 *
 * get_kobj: this needs to be a function that maps the list items to crate::kobj::KObjs
 *
 * This returns the vector of built kobjs that can be then passed to the env to set the last list of
 * things returned, and the row specs that can be used to print out that list.
 */
pub fn build_specs<'a, T, F>(
    cols: &[&str],
    list: &'a List<T>,
    extractors: Option<&HashMap<String, Extractor<T>>>,
    include_index: bool,
    regex: Option<Regex>,
    get_kobj: F,
) -> Vec<(KObj, RowSpec<'a>)>
where
    T: 'a + ListableResource + Metadata<Ty = ObjectMeta>,
    F: Fn(&T) -> KObj,
{
    let mut ret = vec![];
    for item in list.items.iter() {
        let mut row: Vec<CellSpec> = if include_index {
            vec![CellSpec::new_index()]
        } else {
            vec![]
        };
        for col in cols.iter() {
            match *col {
                "Name" => row.push(extract_name(item).into()),
                "Namespace" => row.push(extract_namespace(item).into()),
                "Age" => row.push(extract_age(item).into()),
                _ => match extractors {
                    Some(extractors) => match extractors.get(*col) {
                        Some(extractor) => row.push(extractor(item).into()),
                        None => panic!("Can't extract"),
                    },
                    None => panic!("Can't extract"),
                },
            }
        }
        match regex {
            Some(ref regex) => {
                if row_matches(&row, regex) {
                    ret.push((get_kobj(item), row));
                }
            }
            None => {
                ret.push((get_kobj(item), row));
            }
        }
    }
    ret
}

// common extractors

/// An extractor for the Name field. Extracts the name out of the object metadata
pub fn extract_name<T: Metadata<Ty = ObjectMeta>>(obj: &T) -> Option<Cow<'_, str>> {
    let meta = obj.metadata();
    meta.name.as_ref().map(|n| n.into())
}

/// An extractor for the Age field. Extracts the age out of the object metadata
pub fn extract_age<T: Metadata<Ty = ObjectMeta>>(obj: &T) -> Option<Cow<'_, str>> {
    let meta = obj.metadata();
    meta.creation_timestamp
        .as_ref()
        .map(|ts| time_since(ts.0).into())
}

/// An extractor for the Namespace field. Extracts the namespace out of the object metadata
pub fn extract_namespace<T: Metadata<Ty = ObjectMeta>>(obj: &T) -> Option<Cow<'_, str>> {
    let meta = obj.metadata();
    meta.namespace.as_ref().map(|ns| ns.as_str().into())
}

// utility functions
fn row_matches<'a>(row: &[CellSpec<'a>], regex: &Regex) -> bool {
    let mut has_match = false;
    for cell_spec in row.iter() {
        if !has_match {
            has_match = cell_spec.matches(regex);
        }
    }
    has_match
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

/// Build a multi-line string of the specified keyvals
pub fn keyval_string(keyvals: &BTreeMap<String, String>) -> String {
    let mut buf = String::new();
    for (key, val) in keyvals.iter() {
        buf.push_str(key);
        buf.push('=');
        buf.push_str(val);
        buf.push('\n');
    }
    buf
}

// utility methods for show/sort args

/// Add any specified extra columns
///
/// cols: the vector of columes to show. Any flags to show extra columns will cause the column name
/// to be added to this vector
/// lables: If the --lables flag was specified (deprecated)
/// flags: A vector of the flags that were passed by the user
/// extra_cols: Extra cols to consider. This is a vector of (column_name, flag). If flag is in
/// flags, then column_name is added to cols. The order in this vector is the order columns will be
/// displayed in the output
fn add_extra_cols<'a>(
    cols: &mut Vec<&'a str>,
    labels: bool,
    flags: Vec<&str>,
    extra_cols: &[(&'a str, &'a str)],
) {
    let show_all = flags.iter().any(|e| e.eq_ignore_ascii_case("all"));

    for (flag, col) in extra_cols.iter() {
        if col.eq(&"Labels") {
            if labels || flags.iter().any(|e| e.eq_ignore_ascii_case("labels")) {
                cols.push(col)
            }
        } else if show_all || flags.iter().any(|e| e.eq_ignore_ascii_case(flag)) {
            cols.push(col)
        }
    }
}

pub enum SortFunc<T> {
    Pre(PreExtractSort<T>),
    Post(&'static str), // sort based on column index given
}

/// A function that can sort based on a column, pre extraction
pub struct PreExtractSort<T> {
    cmp: fn(a: &T, b: &T) -> Ordering,
}

fn age_cmp<T: Metadata<Ty = ObjectMeta>>(a: &T, b: &T) -> Ordering {
    let ato = a.metadata().creation_timestamp.as_ref();
    let bto = b.metadata().creation_timestamp.as_ref();
    match (ato, bto) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (Some(at), Some(bt)) => at.0.cmp(&bt.0),
    }
}

/// get a clap arg for sorting. this takes one or two lists of possible values to allow for passing
/// normal and extra cols
fn sort_arg<'a>(cols: &[&'a str], extra_cols: Option<&[&'a str]>) -> Arg<'a, 'a> {
    let arg = Arg::with_name("sort")
        .short("s")
        .long("sort")
        .help(
            "Sort by specified column (if column isn't shown by default, it will \
             be shown)",
        )
        .takes_value(true)
        .case_insensitive(true)
        .possible_values(cols);
    match extra_cols {
        Some(extra) => arg.possible_values(extra),
        None => arg,
    }
}

static SHOW_HELP: &str =
    "Comma separated list (case-insensitive) of extra columns to show in output. \
     Use '--show all' to show all available columns.";
static SHOW_HELP_WITH_LABELS: &str =
    "Comma separated list (case-insensitive) of extra columns to show in output. \
     Use '--show all,labels' to show all available columns. (Note that 'all' doesn't \
     include labels due to thier size)";
/// get a clap arg for showing extra cols.
fn show_arg<'a>(extra_cols: &[&'a str], labels: bool) -> Arg<'a, 'a> {
    let arg = Arg::with_name("show")
        .short("S")
        .long("show")
        .takes_value(true)
        .possible_value("all")
        .possible_values(extra_cols)
        .case_insensitive(true)
        .use_delimiter(true);
    if labels {
        arg.help(SHOW_HELP_WITH_LABELS)
    } else {
        arg.help(SHOW_HELP)
    }
}
