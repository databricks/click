pub mod alias; // commands for alias/unalias
pub mod click; // commands internal to click (setting config values, etc)
pub mod namespaces; // commands relating to namespaces
pub mod nodes; // commands relating to nodes
pub mod pods; //commands relating to pods
pub mod volumes; // commands relating to volumes

use chrono::offset::Utc;
use chrono::DateTime;
use clap::Arg;
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::ObjectMeta, List, ListableResource, Metadata,
};
use prettytable::{Cell, Row};
use regex::Regex;

use crate::env::Env;
use crate::kobj::KObj;
use crate::output::ClickWriter;
use crate::table::CellSpec;

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

// utility types
type RowSpec<'a> = Vec<CellSpec<'a>>;
type Extractor<T> = fn(&T) -> Option<CellSpec<'_>>;

// command definition
/// Just return what we're given.  Useful for no-op closures in
/// command! macro invocation
fn identity<T>(t: T) -> T {
    t
}



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
        .use_delimiter(true);
    if labels {
        arg.help(SHOW_HELP_WITH_LABELS)
    } else {
        arg.help(SHOW_HELP)
    }
}
