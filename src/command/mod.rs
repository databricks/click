pub mod namespaces;

use chrono::offset::Utc;
use chrono::DateTime;
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::ObjectMeta, List, ListableResource, Metadata,
};
use prettytable::Row;
use regex::Regex;

use crate::kobj::KObj;
use crate::output::ClickWriter;
use crate::table::CellSpec;

use std::borrow::Cow;
use std::collections::HashMap;

// table printing
pub fn print_table<'a>(titles: Row, rows: Vec<Vec<CellSpec<'a>>>, writer: &mut ClickWriter) {
    crate::table::print_table_kapi(titles, rows, writer);
}

// row building
type RowSpecs<'a> = Vec<Vec<CellSpec<'a>>>;
type Extractor<T> = fn(&T) -> Option<Cow<'_, str>>;

pub fn build_specs<'a, T, F>(
    cols: Vec<&'static str>,
    list: &'a List<T>,
    include_index: bool,
    extractors: &HashMap<String, Extractor<T>>,
    get_kobj: F,
) -> (Vec<KObj>, RowSpecs<'a>)
where
    T: 'a + ListableResource + Metadata<Ty = ObjectMeta>,
    F: Fn(&T) -> KObj,
{
    let mut rows = vec![];
    let kobjs = list
        .items
        .iter()
        .map(|item| {
            let mut row: Vec<CellSpec> = if include_index {
                vec![CellSpec::new_index()]
            } else {
                vec![]
            };
            for col in cols.iter() {
                match *col {
                    "Name" => row.push(extract_name(item).into()),
                    "Age" => row.push(extract_age(item).into()),
                    _ => match extractors.get(*col) {
                        Some(extractor) => row.push(extractor(item).into()),
                        None => panic!("Can't extract"),
                    },
                }
            }
            rows.push(row);
            get_kobj(item)
        })
        .collect();
    (kobjs, rows)
}

// common extractors

/// An extractor for the Name field. Extracts the name out of the object metadata
pub fn extract_name<'a, T: Metadata<Ty = ObjectMeta>>(obj: &'a T) -> Option<Cow<'a, str>> {
    let meta = obj.metadata();
    meta.name.as_ref().map(|n| n.into())
}

/// An extractor for the Age field. Extracts the age out of the object metadata
pub fn extract_age<'a, T: Metadata<Ty = ObjectMeta>>(obj: &'a T) -> Option<Cow<'a, str>> {
    let meta = obj.metadata();
    meta.creation_timestamp
        .as_ref()
        .map(|ts| time_since(ts.0).into())
}

// utility functions
pub fn filter<'a, I>(things: I, regex: Regex) -> Vec<Vec<CellSpec<'a>>>
where
    I: Iterator<Item = Vec<CellSpec<'a>>>,
{
    things
        .filter(|thing| {
            let mut has_match = false;
            for cell_spec in thing.iter() {
                if !has_match {
                    has_match = cell_spec.matches(&regex);
                }
            }
            has_match
        })
        .collect()
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
