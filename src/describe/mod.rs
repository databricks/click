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

/// This module contains code for handling how click describes various k8s objects
use crate::{command::keyval_string, error::ClickError, output::ClickWriter};
use chrono::Local;
use clap::ArgMatches;
use k8s_openapi::{apimachinery::pkg::apis::meta::v1::ObjectMeta, Metadata, Resource};
use serde::ser::Serialize;
use std::collections::HashSet;

pub mod crd;
pub mod legacy;
pub mod service;

pub static NOTSUPPORTED: &str = "not supported without -j or -y yet\n";

pub fn maybe_full_describe_output<T: ?Sized>(
    matches: &ArgMatches,
    value: &T,
    writer: &mut ClickWriter,
) -> bool
where
    T: Serialize,
{
    if matches.is_present("json") {
        writer.pretty_color_json(value).unwrap_or(());
        true
    } else if matches.is_present("yaml") {
        writer.print_yaml(value).unwrap_or(());
        true
    } else {
        false
    }
}

lazy_static! {
    static ref DESCRIBE_SKIP_KEYS: HashSet<String> = {
        let mut s: HashSet<String> = HashSet::new();
        s.insert("kubectl.kubernetes.io/last-applied-configuration".to_string());
        s
    };
}

pub fn describe_metadata<T: ?Sized + Metadata<Ty = ObjectMeta> + Resource>(
    value: &T,
    table: &mut comfy_table::Table,
) -> Result<(), ClickError> {
    let metadata = value.metadata();
    table.add_row(vec![
        "Name:",
        metadata.name.as_deref().unwrap_or("<Unknown>"),
    ]);
    table.add_row(vec![
        "Namespace:",
        metadata.namespace.as_deref().unwrap_or("<Unknown>"),
    ]);
    table.add_row(vec![
        "Labels:",
        &keyval_string(metadata.labels.iter(), None),
    ]);
    table.add_row(vec![
        "Annotations:",
        &keyval_string(metadata.annotations.iter(), Some(&DESCRIBE_SKIP_KEYS)),
    ]);
    table.add_row(vec!["API Version:", <T as Resource>::API_VERSION]);
    table.add_row(vec!["Kind:", <T as Resource>::KIND]);

    match &metadata.creation_timestamp {
        Some(created) => {
            table.add_row(vec![
                "Created At:",
                &format!("{} ({})", created.0, created.0.with_timezone(&Local)),
            ]);
        }
        None => {
            table.add_row(vec!["Created At:", "<Unknown>"]);
        }
    }

    table.add_row(vec![
        "Generation:",
        metadata
            .generation
            .map(|g| format!("{}", g))
            .as_deref()
            .unwrap_or("<none>"),
    ]);
    table.add_row(vec![
        "Resource Version:",
        metadata.resource_version.as_deref().unwrap_or("<Unknown>"),
    ]);
    table.add_row(vec![
        "Self Link:",
        metadata.self_link.as_deref().unwrap_or("<Unknown>"),
    ]);
    table.add_row(vec!["UID:", metadata.uid.as_deref().unwrap_or("<Unknown>")]);
    Ok(())
}
