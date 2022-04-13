// Copyright 2021 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chrono::offset::Utc;
use chrono::{DateTime, Duration};
use clap::ArgMatches;
use humantime::parse_duration;
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
    http::{self, Request},
    List, ListOptional, ListResponse, ListableResource, Metadata, RequestError, ResponseBody,
};
use prettytable::{Cell, Row};
use regex::Regex;
use serde::Deserialize;

use crate::env::Env;
use crate::error::ClickError;
use crate::kobj::KObj;
use crate::output::ClickWriter;
use crate::table::CellSpec;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::io::{stderr, Write};

#[macro_use]
pub mod command_def;

pub mod alias; // commands for alias/unalias
pub mod click; // commands internal to click (setting config values, etc)
pub mod configmaps; // commands relating to configmaps
pub mod copy; // command to copy files to/from pods
pub mod crds; // commands to query crd created objects
pub mod daemonsets; // commands for daemonsets
pub mod delete; // command to delete objects
pub mod deployments; // command to list deployments
pub mod describe; // the describe command
pub mod events; // commands to print events
pub mod exec; // command to exec into pods
pub mod jobs; // commands relating to jobs
pub mod logs; // command to get pod logs
pub mod namespaces; // commands relating to namespaces
pub mod nodes; // commands relating to nodes
pub mod pods; //commands relating to pods
pub mod portforwards; // commands for forwarding ports
pub mod replicasets; // commands relating to relicasets
pub mod secrets; // commands for secrets
pub mod services; // commands for services
pub mod statefulsets; // commands for statefulsets
pub mod storage; // commands relating to storage objects (like storageclass)
pub mod volumes; // commands relating to volumes

#[cfg(feature = "argorollouts")]
pub mod rollouts;

// utility types
type RowSpec<'a> = Vec<CellSpec<'a>>;
type Extractor<T> = fn(&T) -> Option<CellSpec<'_>>;

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
) -> Result<(), ClickError>
where
    T: ListableResource + Metadata<Ty = ObjectMeta> + for<'de> Deserialize<'de> + Debug,
    F: Fn(&T) -> KObj,
{
    let regex = match crate::table::get_regex(&matches) {
        Ok(r) => r,
        Err(s) => {
            writeln!(stderr(), "{}", s).unwrap_or(());
            return Ok(()); // TODO: Return the error when that does something
        }
    };

    let list_res = env.run_on_context::<_, List<T>>(|c| c.execute_list(request));
    if list_res.is_err() {
        env.clear_last_objs();
    }
    let list = list_res?;

    let mut flags: Vec<&str> = match matches.values_of("show") {
        Some(v) => v.collect(),
        None => vec![],
    };

    let sort = matches.value_of("sort").map(|s| {
        let colname = s.to_lowercase();
        if let Some(col) = mapped_val(&colname, col_map) {
            command_def::SortCol(col)
        } else if let Some(ecm) = extra_col_map {
            let mut func = None;
            for (flag, col) in ecm.iter() {
                if flag.eq(&colname) {
                    flags.push(flag);
                    func = Some(command_def::SortCol(col));
                }
            }
            match func {
                Some(f) => f,
                None => panic!("Shouldn't be allowed to ask to sort by: {}", colname),
            }
        } else {
            panic!("Shouldn't be allowed to ask to sort by: {}", colname);
        }
    });

    if let Some(ecm) = extra_col_map {
        // if we're not in a namespace, we want to add a namespace col if it's in extra_col_map
        if env.namespace.is_none() && mapped_val("namespace", ecm).is_some() {
            flags.push("namespace");
        }

        let labels_present = if matches.is_valid_subcommand("labels") {
            matches.is_present("labels")
        } else {
            false
        };
        command_def::add_extra_cols(&mut cols, labels_present, flags, ecm);
    }

    handle_list_result(
        env,
        writer,
        cols,
        list,
        extractors,
        regex,
        sort,
        matches.is_present("reverse"),
        get_kobj,
    )
}

/// Uppercase the first letter of the given str
pub fn uppercase_first(s: &str) -> String {
    let mut cs = s.chars();
    match cs.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + cs.as_str(),
    }
}

/// a clap validator for duration
fn valid_duration(s: &str) -> Result<(), String> {
    parse_duration(s).map(|_| ()).map_err(|e| e.to_string())
}

/// a clap validator for rfc3339 dates
fn valid_date(s: &str) -> Result<(), String> {
    DateTime::parse_from_rfc3339(s)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// a clap validator for u32
pub fn valid_u32(s: &str) -> Result<(), String> {
    s.parse::<u32>().map(|_| ()).map_err(|e| e.to_string())
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
    list: List<T>,
    extractors: Option<&HashMap<String, Extractor<T>>>,
    regex: Option<Regex>,
    sort: Option<command_def::SortCol>,
    reverse: bool,
    get_kobj: F,
) -> Result<(), ClickError>
where
    T: 'a + ListableResource + Metadata<Ty = ObjectMeta>,
    F: Fn(&T) -> KObj,
{
    let mut specs = build_specs(&cols, &list, extractors, true, regex, get_kobj);

    let mut titles: Vec<Cell> = vec![Cell::new("####")];
    titles.reserve(cols.len());
    for col in cols.iter() {
        titles.push(Cell::new(col));
    }

    if let Some(command_def::SortCol(colname)) = sort {
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

    crate::table::print_table(Row::new(titles), rows, writer);
    env.set_last_objs(kobjs);
    Ok(())
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
                "Age" => row.push(extract_age(item).into()),
                "Labels" => row.push(extract_labels(item).into()),
                "Name" => row.push(extract_name(item).into()),
                "Namespace" => row.push(extract_namespace(item).into()),
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
pub fn extract_age<T: Metadata<Ty = ObjectMeta>>(obj: &T) -> Option<CellSpec<'_>> {
    let meta = obj.metadata();
    meta.creation_timestamp.as_ref().map(|ts| ts.0.into())
}

/// An extractor for the Namespace field. Extracts the namespace out of the object metadata
pub fn extract_namespace<T: Metadata<Ty = ObjectMeta>>(obj: &T) -> Option<Cow<'_, str>> {
    let meta = obj.metadata();
    meta.namespace.as_ref().map(|ns| ns.as_str().into())
}

/// An extractor for the Labels field. Extracts the labels out of the object metadata
pub fn extract_labels<T: Metadata<Ty = ObjectMeta>>(obj: &T) -> Option<Cow<'_, str>> {
    let meta = obj.metadata();
    Some(keyval_string(&meta.labels).into())
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

pub fn format_duration(duration: Duration) -> String {
    if duration.num_days() > 365 {
        // TODO: maybe be more smart about printing years, or at least have an option
        let days = duration.num_days();
        let yrs = days / 365;
        format!("{}y {}d", yrs, (duration.num_days() - (yrs * 365)))
    } else if duration.num_days() > 0 {
        format!(
            "{}d {}h",
            duration.num_days(),
            (duration.num_hours() - (24 * duration.num_days()))
        )
    } else if duration.num_hours() > 0 {
        format!(
            "{}h {}m",
            duration.num_hours(),
            (duration.num_minutes() - (60 * duration.num_hours()))
        )
    } else if duration.num_minutes() > 0 {
        format!(
            "{}m {}s",
            duration.num_minutes(),
            (duration.num_seconds() - (60 * duration.num_minutes()))
        )
    } else {
        format!("{}s", duration.num_seconds())
    }
}

pub fn time_since(date: DateTime<Utc>) -> Duration {
    let now = Utc::now();
    now.signed_duration_since(date)
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

// utils for getting custom requests

/// Get a read request for a custom url
// used by features, so without them isn't used
// type is from k8s_openapi, so we can't change it
#[allow(dead_code, clippy::type_complexity)]
pub fn get_read_request_for_url<T: k8s_openapi::Response>(
    url: String,
) -> Result<(Request<Vec<u8>>, fn(_: http::StatusCode) -> ResponseBody<T>), RequestError> {
    let request = http::Request::get(url);
    let body = vec![];
    match request.body(body) {
        Ok(request) => Ok((request, ResponseBody::new)),
        Err(err) => Err(RequestError::Http(err)),
    }
}

/// Get a request for a custom url. The item must be listable.
// used by features, so without them isn't used
// type is from k8s_openapi, so we can't change it
#[allow(dead_code, clippy::type_complexity)]
pub fn get_list_request_for_url<T: ListableResource + for<'de> serde::Deserialize<'de>>(
    url: String,
    optional: ListOptional<'_>,
) -> Result<
    (
        Request<Vec<u8>>,
        fn(_: http::StatusCode) -> ResponseBody<ListResponse<T>>,
    ),
    RequestError,
> {
    let mut query_pairs = url::form_urlencoded::Serializer::new(url);
    optional.__serialize(&mut query_pairs);
    let __url = query_pairs.finish();
    let __request = Request::get(__url);
    let __body = vec![];
    match __request.body(__body) {
        Ok(request) => Ok((request, ResponseBody::new)),
        Err(err) => Err(RequestError::Http(err)),
    }
}
