use ansi_term::Colour::Yellow;
use clap::App;
use k8s_openapi::ListOptional;
use k8s_openapi::{api::core::v1 as api, http::Request, List};
use prettytable::{Cell, Row, Table};
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    command::time_since,
    completer,
    env::{Env, ObjectSelection},
    kobj::KObj,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::cmp;
use std::collections::HashMap;
use std::io::Write;

fn event_cmp(e1: &api::Event, e2: &api::Event) -> cmp::Ordering {
    match (e1.last_timestamp.as_ref(), e2.last_timestamp.as_ref()) {
        (None, None) => cmp::Ordering::Equal,
        (None, Some(_)) => cmp::Ordering::Less,
        (Some(_), None) => cmp::Ordering::Greater,
        (Some(e1ts), Some(e2ts)) => e1ts.partial_cmp(e2ts).unwrap(),
    }
}

fn print_events_for_obj(obj: &KObj, env: &Env, writer: &mut ClickWriter) {
    let mut opts: ListOptional = Default::default();
    let mut include_namespace = false;
    let (request, _body) = if let Some(ns) = obj.namespace.as_ref() {
        let fs = format!(
            "involvedObject.name={},involvedObject.namespace={}",
            obj.name(),
            ns
        );
        opts.field_selector = Some(&fs);
        api::Event::list_namespaced_event(ns, opts).unwrap()
    } else {
        include_namespace = true;
        let fs = format!("involvedObject.name={}", obj.name(),);
        opts.field_selector = Some(&fs);
        api::Event::list_event_for_all_namespaces(opts).unwrap()
    };
    print_events(request, env, writer, include_namespace, false);
}

fn print_events_no_obj(env: &Env, writer: &mut ClickWriter) {
    let mut opts: ListOptional = Default::default();
    let mut include_namespace = false;
    let (request, _body) = if let Some(ns) = env.namespace.as_ref() {
        let fs = format!("involvedObject.namespace={}", ns);
        opts.field_selector = Some(&fs);
        api::Event::list_namespaced_event(ns, opts).unwrap()
    } else {
        include_namespace = true;
        api::Event::list_event_for_all_namespaces(opts).unwrap()
    };
    print_events(request, env, writer, include_namespace, true);
}

fn print_events(
    request: Request<Vec<u8>>,
    env: &Env,
    writer: &mut ClickWriter,
    include_namespace: bool,
    include_object: bool,
) {
    let events_opt: Option<List<api::Event>> = env.run_on_context(|c| c.execute_list(request));
    match events_opt {
        Some(mut event_list) => {
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
                    let timestr = match event.last_timestamp.as_ref() {
                        Some(ts) => time_since(ts.0),
                        None => event
                            .event_time
                            .as_ref()
                            .map(|t| time_since(t.0))
                            .unwrap_or_else(|| "unknown".to_string()),
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
        }
        None => {
            clickwriteln!(writer, "Failed to fetch events");
        }
    }
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
            print_events_no_obj(env, writer);
        } else {
            env.apply_to_selection(
                writer,
                Some(&env.click_config.range_separator),
                |obj, writer| {
                    print_events_for_obj(obj, env, writer);
                },
            );
        }
    }
);
