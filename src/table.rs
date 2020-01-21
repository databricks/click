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

/// Stuff to handle outputting a table of resources, including
/// applying filters and sorting
use output::ClickWriter;

use clap::ArgMatches;
use prettytable::Cell;
use prettytable::Row;
use prettytable::{format, Table};
use regex::Regex;

use std::cmp::Ordering;
use std::io::Write;

lazy_static! {
    static ref TBLFMT: format::TableFormat = format::FormatBuilder::new()
        .separators(
            &[format::LinePosition::Title, format::LinePosition::Bottom],
            format::LineSeparator::new('-', '+', '+', '+')
        )
        .padding(1, 1)
        .build();
}

enum CellSpecTxt<'a> {
    Index,
    Str(&'a str),
    String(String),
}

/// Holds a specification for a prettytable cell
pub struct CellSpec<'a> {
    txt: CellSpecTxt<'a>,
    pub style: Option<&'a str>,
    pub align: Option<format::Alignment>,
}

impl<'a> CellSpec<'a> {
    pub fn new(txt: &'a str) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Str(txt),
            style: None,
            align: None,
        }
    }

    pub fn new_owned(txt: String) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::String(txt),
            style: None,
            align: None,
        }
    }

    pub fn new_index() -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Index,
            style: None,
            align: None,
        }
    }

    pub fn with_style(txt: &'a str, style: &'a str) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Str(txt),
            style: Some(style),
            align: None,
        }
    }

    pub fn with_style_owned(txt: String, style: &'a str) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::String(txt),
            style: Some(style),
            align: None,
        }
    }

    pub fn with_align_owned(txt: String, align: format::Alignment) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::String(txt),
            style: None,
            align: Some(align),
        }
    }

    pub fn to_cell(&self, index: usize) -> Cell {
        let mut cell = match self.txt {
            CellSpecTxt::Index => {
                let mut c = Cell::new(format!("{}", index).as_str());
                c.align(format::Alignment::RIGHT);
                c
            }
            CellSpecTxt::Str(ref s) => Cell::new(s),
            CellSpecTxt::String(ref s) => Cell::new(s.as_str()),
        };

        if let Some(a) = self.align {
            cell.align(a);
        }

        if let Some(style) = self.style {
            cell.style_spec(style)
        } else {
            cell
        }
    }

    pub fn matches(&self, regex: &Regex) -> bool {
        match self.txt {
            CellSpecTxt::Index => false,
            CellSpecTxt::Str(ref s) => regex.is_match(s),
            CellSpecTxt::String(ref s) => regex.is_match(s),
        }
    }
}

pub fn get_regex(matches: &ArgMatches) -> Result<Option<Regex>, String> {
    match matches.value_of("regex") {
        Some(pattern) => {
            if let Ok(regex) = Regex::new(pattern) {
                Ok(Some(regex))
            } else {
                Err(format!("Invalid regex: {}", pattern))
            }
        }
        None => Ok(None),
    }
}

pub fn filter<'a, T, I>(things: I, regex: Regex) -> Vec<(T, Vec<CellSpec<'a>>)>
where
    I: Iterator<Item = (T, Vec<CellSpec<'a>>)>,
{
    things
        .filter(|thing| {
            let mut has_match = false;
            for cell_spec in thing.1.iter() {
                if !has_match {
                    has_match = cell_spec.matches(&regex);
                }
            }
            has_match
        })
        .collect()
}

pub fn opt_sort<T, F>(o1: Option<T>, o2: Option<T>, f: F) -> Ordering
where
    F: Fn(&T, &T) -> Ordering,
{
    match (o1, o2) {
        (Some(ref v1), Some(ref v2)) => f(v1, v2),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn term_print_table<T: Write>(table: &Table, writer: &mut T) -> bool {
    match term::TerminfoTerminal::new(writer) {
        Some(ref mut term) => {
            table.print_term(term).unwrap_or(0);
            true
        }
        None => false,
    }
}

pub fn print_filled_table(table: &mut Table, writer: &mut ClickWriter) {
    table.set_format(TBLFMT.clone());
    if !term_print_table(&table, writer) {
        table.print(writer).unwrap_or(0);
    }
}

#[allow(clippy::ptr_arg)]
pub fn print_table<'a, T>(
    table: &mut Table,
    specs: &Vec<(T, Vec<CellSpec<'a>>)>,
    writer: &mut ClickWriter,
) {
    for (index, t_spec) in specs.iter().enumerate() {
        let row_vec: Vec<Cell> = t_spec.1.iter().map(|spec| spec.to_cell(index)).collect();
        table.add_row(Row::new(row_vec));
    }
    table.set_format(TBLFMT.clone());
    if !term_print_table(&table, writer) {
        table.print(writer).unwrap_or(0);
    }
}
