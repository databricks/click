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

use ansi_term::Colour::Yellow;
use chrono::{offset::Utc, DateTime};
use clap::App;
use k8s_openapi::ListOptional;
use k8s_openapi::{api::core::v1 as api, http::Request, List};
use prettytable::{Cell, Row, Table};
use rustyline::completion::Pair as RustlinePair;

use crate::command::format_duration;
use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    command::time_since,
    completer,
    env::{Env, ObjectSelection},
    error::ClickError,
    kobj::KObj,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::cmp;
use std::collections::HashMap;
use std::io::Write;

// try and get a timestamp for the event. we look in last_timestamp, and if that's not present, just
// event_time
fn get_event_ts(event: &api::Event) -> Option<DateTime<Utc>> {
    match &event.last_timestamp {
        Some(ts) => Some(ts.0),
        None => event.event_time.as_ref().map(|ts| ts.0),
    }
}

fn event_cmp(e1: &api::Event, e2: &api::Event) -> cmp::Ordering {
    match (get_event_ts(e1), get_event_ts(e2)) {
        (None, None) => cmp::Ordering::Equal,
        (None, Some(_)) => cmp::Ordering::Less,
        (Some(_), None) => cmp::Ordering::Greater,
        (Some(e1ts), Some(e2ts)) => e1ts.partial_cmp(&e2ts).unwrap(),
    }
}

pub fn print_events_for_obj(
    obj: &KObj,
    env: &Env,
    writer: &mut ClickWriter,
) -> Result<(), ClickError> {
    let mut opts: ListOptional = Default::default();
    let mut include_namespace = false;
    let (request, _body) = if let Some(ns) = obj.namespace.as_ref() {
        let fs = format!(
            "involvedObject.name={},involvedObject.namespace={}",
            obj.name(),
            ns
        );
        opts.field_selector = Some(&fs);
        api::Event::list_namespaced_event(ns, opts)?
    } else {
        include_namespace = true;
        let fs = format!("involvedObject.name={}", obj.name(),);
        opts.field_selector = Some(&fs);
        api::Event::list_event_for_all_namespaces(opts)?
    };
    print_events(request, env, writer, include_namespace, false)
}

fn print_events_no_obj(env: &Env, writer: &mut ClickWriter) -> Result<(), ClickError> {
    let mut opts: ListOptional = Default::default();
    let mut include_namespace = false;
    let (request, _body) = if let Some(ns) = env.namespace.as_ref() {
        let fs = format!("involvedObject.namespace={}", ns);
        opts.field_selector = Some(&fs);
        api::Event::list_namespaced_event(ns, opts)?
    } else {
        include_namespace = true;
        api::Event::list_event_for_all_namespaces(opts)?
    };
    print_events(request, env, writer, include_namespace, true)
}

fn print_events(
    request: Request<Vec<u8>>,
    env: &Env,
    writer: &mut ClickWriter,
    include_namespace: bool,
    include_object: bool,
) -> Result<(), ClickError> {
    let mut event_list: List<api::Event> = env.run_on_context(|c| c.execute_list(request))?;
    if !event_list.items.is_empty() {
        event_list.items.sort_by(event_cmp);
        let mut table = Table::new();
        let mut titles = if include_namespace {
            vec![
                cell!("Namespace"),
                cell!("Last Seen"),
                cell!("Type"),
                cell!("Reason"),
            ]
        } else {
            vec![cell!("Last Seen"), cell!("Type"), cell!("Reason")]
        };
        if include_object {
            titles.push(cell!("Object"));
        }
        titles.push(cell!("Message"));
        table.set_titles(Row::new(titles));
        for event in event_list.items.iter() {
            let mut row: Vec<Cell> = Vec::new();
            if include_namespace {
                row.push(Cell::new(
                    event.metadata.namespace.as_deref().unwrap_or("unknown"),
                ));
            }
            let timestr = match get_event_ts(event) {
                Some(ts) => format_duration(time_since(ts)),
                None => "unknown".to_string(),
            };
            row.push(Cell::new(&timestr));
            row.push(Cell::new(event.type_.as_deref().unwrap_or("unknown")));
            row.push(Cell::new(event.reason.as_deref().unwrap_or("unknown")));
            if include_object {
                row.push(Cell::new(
                    event.involved_object.name.as_deref().unwrap_or("unknown"),
                ));
            }
            row.push(Cell::new(event.message.as_deref().unwrap_or("<none>")));
            table.add_row(Row::new(row));
        }
        table.set_format(*crate::table::TBLFMT);
        table.print(writer).unwrap_or(0);
    } else {
        clickwriteln!(writer, "No events");
    }
    Ok(())
}

command!(
    Events,
    "events",
    "Get events for the active pod",
    crate::command::command_def::identity,
    vec!["events"],
    noop_complete!(),
    no_named_complete!(),
    |_matches, env, writer| {
        if let ObjectSelection::None = env.current_selection() {
            print_events_no_obj(env, writer)
        } else {
            env.apply_to_selection(
                writer,
                Some(&env.click_config.range_separator),
                |obj, writer| print_events_for_obj(obj, env, writer),
            )
        }
    }
);
