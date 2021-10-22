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

use crate::command::format_duration;
/// Stuff to handle outputting a table of resources, including
/// applying filters and sorting
use crate::output::ClickWriter;

use chrono::Duration;
use clap::ArgMatches;
use prettytable::Cell;
use prettytable::Row;
use prettytable::{format, Table};
use regex::Regex;

use std::borrow::Cow;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::io::Write;

lazy_static! {
    pub static ref TBLFMT: format::TableFormat = format::FormatBuilder::new()
        .separators(
            &[format::LinePosition::Title, format::LinePosition::Bottom],
            format::LineSeparator::new('-', '+', '+', '+')
        )
        .padding(1, 1)
        .build();
}

#[derive(Debug)]
enum CellSpecTxt<'a> {
    Index,
    Int(i64),
    Duration(Duration),
    Str(Cow<'a, str>),
}

/// Holds a specification for a prettytable cell
pub struct CellSpec<'a> {
    txt: CellSpecTxt<'a>,
    pub style: Option<&'a str>,
    pub align: Option<format::Alignment>,
}

impl<'a> CellSpec<'a> {
    pub fn new_index() -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Index,
            style: None,
            align: None,
        }
    }

    pub fn new_int(num: i64) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Int(num),
            style: None,
            align: None,
        }
    }

    pub fn with_style(txt: Cow<'a, str>, style: &'a str) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Str(txt),
            style: Some(style),
            align: None,
        }
    }

    pub fn _with_align(txt: Cow<'a, str>, align: format::Alignment) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Str(txt),
            style: None,
            align: Some(align),
        }
    }

    pub fn to_cell(&self, index: usize) -> Cell {
        let mut cell = match &self.txt {
            CellSpecTxt::Duration(duration) => {
                Cell::new(&format_duration(*duration))
            }
            CellSpecTxt::Index => {
                let mut c = Cell::new(format!("{}", index).as_str());
                c.align(format::Alignment::RIGHT);
                c
            }
            CellSpecTxt::Int(num) => {
                let mut c = Cell::new(format!("{}", num).as_str());
                c.align(format::Alignment::RIGHT);
                c
            }
            CellSpecTxt::Str(s) => Cell::new(s),
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
        match &self.txt {
            CellSpecTxt::Index => false,
            CellSpecTxt::Str(s) => regex.is_match(s),
            _ => {
                regex.is_match(&self.to_string())
            }
        }
    }
}

impl <'a> ToString for CellSpec<'a> {
    fn to_string(&self) -> String {
        match &self.txt {
            CellSpecTxt::Index => "[index]".to_string(),
            CellSpecTxt::Int(num) => format!("{}", num),
            CellSpecTxt::Duration(duration) => format_duration(*duration),
            CellSpecTxt::Str(s) => s.to_string(),
        }
    }
}

impl<'a> From<&'a str> for CellSpec<'a> {
    fn from(s: &'a str) -> Self {
        CellSpec {
            txt: CellSpecTxt::Str(Cow::Borrowed(s)),
            style: None,
            align: None,
        }
    }
}

impl<'a> From<Cow<'a, str>> for CellSpec<'a> {
    fn from(c: Cow<'a, str>) -> Self {
        CellSpec {
            txt: CellSpecTxt::Str(c),
            style: None,
            align: None,
        }
    }
}

impl<'a> From<String> for CellSpec<'a> {
    fn from(s: String) -> Self {
        CellSpec {
            txt: CellSpecTxt::Str(Cow::Owned(s)),
            style: None,
            align: None,
        }
    }
}

impl<'a> From<i64> for CellSpec<'a> {
    fn from(num: i64) -> Self {
        CellSpec::new_int(num)
    }
}

impl<'a> From<i32> for CellSpec<'a> {
    fn from(num: i32) -> Self {
        CellSpec::new_int(num as i64)
    }
}

impl<'a> From<usize> for CellSpec<'a> {
    fn from(num: usize) -> Self {
        CellSpec::new_int(num as i64)
    }
}

impl<'a> From<Duration> for CellSpec<'a> {
    fn from(duration: Duration) -> Self {
        CellSpec {
            txt: CellSpecTxt::Duration(duration),
            style: None,
            align: None,
        }
    }
}

impl<'a, T> From<Option<T>> for CellSpec<'a>
where
    T: Into<CellSpec<'a>>,
{
    fn from(opt: Option<T>) -> Self {
        match opt {
            Some(v) => v.into(),
            None => "Unknown".into(),
        }
    }
}
impl<'a> PartialEq for CellSpec<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.txt, &other.txt) {
            (CellSpecTxt::Index, CellSpecTxt::Index) => true,
            (CellSpecTxt::Str(st), CellSpecTxt::Str(ot)) => st == ot,
            (CellSpecTxt::Int(num1), CellSpecTxt::Int(num2)) => num1 == num2,
            (CellSpecTxt::Duration(dur1), CellSpecTxt::Duration(dur2)) => dur1 == dur2,
            _ => false,
        }
    }
}
impl<'a> Eq for CellSpec<'a> {}

impl<'a> PartialOrd for CellSpec<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (&self.txt, &other.txt) {
            (CellSpecTxt::Index, CellSpecTxt::Index) => Some(Ordering::Equal),
            (CellSpecTxt::Str(st), CellSpecTxt::Str(ot)) => st.partial_cmp(ot),
            (CellSpecTxt::Int(num1), CellSpecTxt::Int(num2)) => num1.partial_cmp(num2),
            (CellSpecTxt::Duration(dur1), CellSpecTxt::Duration(dur2)) => dur1.partial_cmp(dur2),
            _ => None,
        }
    }
}

impl<'a> Ord for CellSpec<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.partial_cmp(other) {
            Some(o) => o,
            None => Ordering::Equal,
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
    table.set_format(*TBLFMT);
    if !term_print_table(table, writer) {
        table.print(writer).unwrap_or(0);
    }
}

#[allow(clippy::ptr_arg)]
pub fn print_table(titles: Row, specs: Vec<Vec<CellSpec<'_>>>, writer: &mut ClickWriter) {
    let mut table = Table::new();
    table.set_titles(titles);
    for (index, t_spec) in specs.iter().enumerate() {
        let row_vec: Vec<Cell> = t_spec.iter().map(|spec| spec.to_cell(index)).collect();
        table.add_row(Row::new(row_vec));
    }
    table.set_format(*TBLFMT);
    if !term_print_table(&table, writer) {
        table.print(writer).unwrap_or(0);
    }
}
