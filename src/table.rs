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
use crate::command::time_since;
/// Stuff to handle outputting a table of resources, including
/// applying filters and sorting
use crate::output::ClickWriter;

use chrono::{DateTime, Duration, Utc};
use clap::ArgMatches;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
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

// TODO: Add config to use acsii style
//pub const ASCII_TABLE_STYLE: &str = "   - --       -    ";
pub const UTF8_TABLE_STYLE: &str =  "   ─ ══       ─    ";

#[derive(Debug)]
enum CellSpecTxt<'a> {
    DateTime(DateTime<Utc>),
    Duration(Duration),
    Index,
    Int(i64),
    None,
    Quantity(Quantity),
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
            CellSpecTxt::DateTime(datetime) => Cell::new(&format_duration(time_since(*datetime))),
            CellSpecTxt::Duration(duration) => Cell::new(&format_duration(*duration)),
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
            CellSpecTxt::None => Cell::new("Unknown/None"),
            CellSpecTxt::Quantity(quant) => Cell::new(&quant.0),
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
            CellSpecTxt::Quantity(quant) => regex.is_match(&quant.0),
            CellSpecTxt::Index => false,
            CellSpecTxt::Str(s) => regex.is_match(s),
            _ => regex.is_match(&self.to_string()),
        }
    }
}

impl<'a> ToString for CellSpec<'a> {
    fn to_string(&self) -> String {
        match &self.txt {
            CellSpecTxt::DateTime(datetime) => format_duration(time_since(*datetime)),
            CellSpecTxt::Duration(duration) => format_duration(*duration),
            CellSpecTxt::Index => "[index]".to_string(),
            CellSpecTxt::Int(num) => format!("{}", num),
            CellSpecTxt::None => "Unknown/None".to_string(),
            CellSpecTxt::Quantity(quant) => quant.0.clone(),
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

impl<'a> From<Quantity> for CellSpec<'a> {
    fn from(quant: Quantity) -> Self {
        CellSpec {
            txt: CellSpecTxt::Quantity(quant),
            style: None,
            align: None,
        }
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

impl<'a> From<DateTime<Utc>> for CellSpec<'a> {
    fn from(dt: DateTime<Utc>) -> Self {
        CellSpec {
            txt: CellSpecTxt::DateTime(dt),
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
            None => CellSpec {
                txt: CellSpecTxt::None,
                style: None,
                align: None,
            },
        }
    }
}
impl<'a> PartialEq for CellSpec<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.txt, &other.txt) {
            (CellSpecTxt::DateTime(dt1), CellSpecTxt::DateTime(dt2)) => dt1.eq(dt2),
            (CellSpecTxt::Duration(dur1), CellSpecTxt::Duration(dur2)) => dur1 == dur2,
            (CellSpecTxt::Index, CellSpecTxt::Index) => true,
            (CellSpecTxt::Int(num1), CellSpecTxt::Int(num2)) => num1 == num2,
            (CellSpecTxt::None, CellSpecTxt::None) => true,
            (CellSpecTxt::Quantity(quant1), CellSpecTxt::Quantity(quant2)) => quant1 == quant2,
            (CellSpecTxt::Str(st), CellSpecTxt::Str(ot)) => st == ot,
            _ => false,
        }
    }
}
impl<'a> Eq for CellSpec<'a> {}

impl<'a> PartialOrd for CellSpec<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (&self.txt, &other.txt) {
            (CellSpecTxt::DateTime(dt1), CellSpecTxt::DateTime(dt2)) => dt1.partial_cmp(dt2),
            (CellSpecTxt::Duration(dur1), CellSpecTxt::Duration(dur2)) => dur1.partial_cmp(dur2),
            (CellSpecTxt::Index, CellSpecTxt::Index) => Some(Ordering::Equal),
            (CellSpecTxt::Int(num1), CellSpecTxt::Int(num2)) => num1.partial_cmp(num2),
            (CellSpecTxt::None, CellSpecTxt::None) => Some(Ordering::Equal),
            (CellSpecTxt::Quantity(quant1), CellSpecTxt::Quantity(quant2)) => {
                raw_quantity(quant1).partial_cmp(&raw_quantity(quant2))
            }
            (CellSpecTxt::Str(st), CellSpecTxt::Str(ot)) => st.partial_cmp(ot),
            (CellSpecTxt::None, _) => Some(Ordering::Greater), // none is the least
            (_, CellSpecTxt::None) => Some(Ordering::Less),    // none is the least
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

// convert a Quantity to a raw number. We assume the quantity has been serialized according to
// the rules in the docs such that:
//  Before serializing, Quantity will be put in “canonical form”. This means that Exponent/suffix
//  will be adjusted up or down (with a corresponding increase or decrease in Mantissa) such that:
//  a. No precision is lost b. No fractional digits will be emitted c. The exponent (or suffix) is
//  as large as possible. The sign will be omitted unless the number is negative.
// Specifically we assume no fractional quantity.
// Anything with an invalid format is converted to 0.0
pub fn raw_quantity(quantity: &Quantity) -> f64 {
    let mut chars = quantity.0.chars().peekable();
    let has_neg = chars.peek().unwrap_or(&'+').eq(&'-');
    if has_neg {
        chars.next();
    }

    // find location of first non-digit
    let mut split = match chars.position(|c| !c.is_digit(10)) {
        Some(pos) => pos,
        None => {
            // no non digit, just parse as a raw number, set split to end of string
            let mut len = quantity.0.len();
            if has_neg {
                len -= 1; // since we'll add one below :)
            }
            len
        }
    };

    if has_neg {
        split += 1; // shift over for the -
    }

    let digits = if has_neg {
        &quantity.0[1..split]
    } else {
        &quantity.0[..split]
    };

    let amt = digits.parse::<i64>().unwrap();
    let suffix = &quantity.0[split..];

    let base10: i64 = 10;

    if suffix.len() > 1 && (suffix.starts_with('e') || suffix.starts_with('E')) {
        // our suffix has more than one char and starts with e/E, so it should be a decimal exponent
        match (&suffix[1..]).parse::<u32>() {
            Ok(exp) => {
                let famt = (amt * base10.pow(exp)) as f64;
                if has_neg {
                    return -famt;
                } else {
                    return famt;
                }
            }
            Err(_) => {
                println!("Invalid suffix for quantity: {}", suffix);
                return 0.0;
            }
        }
    }

    let bytes = match suffix {
        "" => amt,
        "m" => {
            // this is the only branch that could actually produce a fraction, so we handle it
            // specially
            let famt = amt as f64;
            let famt = famt / (base10.pow(3) as f64);
            if has_neg {
                return -famt;
            } else {
                return famt;
            }
        }
        "Ki" => (amt * 2) << 9,
        "Mi" => (amt * 2) << 19,
        "Gi" => (amt * 2) << 29,
        "Ti" => (amt * 2) << 39,
        "Pi" => (amt * 2) << 49,
        "Ei" => (amt * 2) << 59,
        "k" => amt * base10.pow(3),
        "M" => amt * base10.pow(6),
        "G" => amt * base10.pow(9),
        "T" => amt * base10.pow(12),
        "P" => amt * base10.pow(15),
        "E" => amt * base10.pow(18),
        _ => {
            println!("Invalid suffix for quantity {}", suffix);
            0
        }
    };

    if has_neg {
        -bytes as f64
    } else {
        bytes as f64
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

#[cfg(test)]
mod tests {
    use crate::table::raw_quantity;
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

    #[test]
    fn test_raw_quantity() {
        assert_eq!(raw_quantity(&Quantity("1500m".to_string())), 1.5);
        assert_eq!(raw_quantity(&Quantity("-1500m".to_string())), -1.5);
        assert_eq!(raw_quantity(&Quantity("1Ki".to_string())), 1024.0);
        assert_eq!(raw_quantity(&Quantity("2Gi".to_string())), 2147483648.0);
        assert_eq!(raw_quantity(&Quantity("12e6".to_string())), 12000000.0);
        assert_eq!(raw_quantity(&Quantity("12E6".to_string())), 12000000.0);
        assert_eq!(raw_quantity(&Quantity("-22E6".to_string())), -22000000.0);
        assert_eq!(raw_quantity(&Quantity("3G".to_string())), 3000000000.0);
        assert_eq!(raw_quantity(&Quantity("34".to_string())), 34.0);
        assert_eq!(raw_quantity(&Quantity("-3456".to_string())), -3456.0);
    }
}
