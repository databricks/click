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
use std::{collections::HashSet, io::Write};

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
    writer: &mut ClickWriter,
) -> Result<(), ClickError> {
    let metadata = value.metadata();
    writeln!(
        writer,
        "Name:\t\t{}",
        metadata.name.as_deref().unwrap_or("<Unknown>")
    )?;
    writeln!(
        writer,
        "Namespace:\t{}",
        metadata.namespace.as_deref().unwrap_or("<Unknown>")
    )?;
    write!(
        writer,
        "Labels:\t\t{}",
        keyval_string(&metadata.labels, Some("\t\t"), None)
    )?;
    write!(
        writer,
        "Annotations:\t{}",
        keyval_string(
            &metadata.annotations,
            Some("\t\t"),
            Some(&DESCRIBE_SKIP_KEYS)
        )
    )?;
    writeln!(writer, "API Version:\t{}", <T as Resource>::API_VERSION)?;
    writeln!(writer, "Kind:\t\t{}", <T as Resource>::KIND)?;
    match &metadata.creation_timestamp {
        Some(created) => writeln!(
            writer,
            "Created At:\t{} ({})",
            created.0,
            created.0.with_timezone(&Local)
        )?,
        None => writeln!(writer, "Created At:\t<Unknown>")?,
    }
    writeln!(
        writer,
        "Generation\t{}",
        metadata
            .generation
            .map(|g| format!("{}", g))
            .as_deref()
            .unwrap_or("<none>")
    )?;
    writeln!(
        writer,
        "ResourceVersn:\t{}",
        metadata.resource_version.as_deref().unwrap_or("<Unknown>")
    )?;
    writeln!(
        writer,
        "Self Link:\t{}",
        metadata.self_link.as_deref().unwrap_or("<Unknown>")
    )?;
    writeln!(
        writer,
        "UID:\t\t{}",
        metadata.uid.as_deref().unwrap_or("<Unknown>")
    )?;
    Ok(())
}
