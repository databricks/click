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
use crate::env::Env;
/// Stuff to handle outputting a table of resources, including
/// applying filters and sorting
use crate::output::ClickWriter;

use chrono::{DateTime, Duration, Utc};
use clap::ArgMatches;
use comfy_table::{Cell, CellAlignment, Color};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use regex::Regex;

use std::borrow::Cow;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::io::Write;

// TODO: Add config to use acsii style
//pub const ASCII_TABLE_STYLE: &str = "   - --       -    ";
pub const UTF8_TABLE_STYLE: &str = "   ─ ══       ─    ";

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

pub enum ColorType {
    Info,
    Success,
    Warn,
    Danger,
}

// An enum to hold either an actual color, or a color type like "success"
pub enum TableColor {
    Color(Color),
    ColorType(ColorType),
}

impl TableColor {
    fn to_color(&self, env: &Env) -> Color {
        match self {
            TableColor::Color(color) => *color,
            TableColor::ColorType(color_type) => match color_type {
                ColorType::Info => env.styles.info_color(),
                ColorType::Success => env.styles.success_color(),
                ColorType::Warn => env.styles.warning_color(),
                ColorType::Danger => env.styles.danger_color(),
            },
        }
    }
}

impl From<Color> for TableColor {
    fn from(color: Color) -> Self {
        TableColor::Color(color)
    }
}

impl From<ColorType> for TableColor {
    fn from(color_type: ColorType) -> Self {
        TableColor::ColorType(color_type)
    }
}

/// Holds a specification for a table cell
pub struct CellSpec<'a> {
    txt: CellSpecTxt<'a>,
    pub fg: Option<TableColor>,
    pub bg: Option<TableColor>,
    pub align: Option<CellAlignment>,
}

impl<'a> CellSpec<'a> {
    pub fn new_index() -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Index,
            fg: None,
            bg: None,
            align: None,
        }
    }

    pub fn new_int(num: i64) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Int(num),
            fg: None,
            bg: None,
            align: None,
        }
    }

    pub fn with_colors(
        txt: Cow<'a, str>,
        fg: Option<TableColor>,
        bg: Option<TableColor>,
    ) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Str(txt),
            fg,
            bg,
            align: None,
        }
    }

    pub fn _with_align(txt: Cow<'a, str>, align: CellAlignment) -> CellSpec<'a> {
        CellSpec {
            txt: CellSpecTxt::Str(txt),
            fg: None,
            bg: None,
            align: Some(align),
        }
    }

    pub fn to_cell(&self, index: usize, env: &Env) -> Cell {
        let cell = match &self.txt {
            CellSpecTxt::DateTime(datetime) => Cell::new(format_duration(time_since(*datetime))),
            CellSpecTxt::Duration(duration) => Cell::new(format_duration(*duration)),
            CellSpecTxt::Index => {
                Cell::new(format!("{index}").as_str()).set_alignment(CellAlignment::Right)
            }
            CellSpecTxt::Int(num) => {
                Cell::new(format!("{num}").as_str()).set_alignment(CellAlignment::Right)
            }
            CellSpecTxt::None => Cell::new("Unknown/None"),
            CellSpecTxt::Quantity(quant) => Cell::new(&quant.0),
            CellSpecTxt::Str(s) => Cell::new(s),
        };

        let cell = if let Some(a) = self.align {
            cell.set_alignment(a)
        } else {
            cell
        };

        let cell = if let Some(fg) = &self.fg {
            cell.fg(fg.to_color(env))
        } else {
            cell
        };

        if let Some(bg) = &self.bg {
            cell.bg(bg.to_color(env))
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

impl<'a> std::fmt::Display for CellSpec<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self.txt {
                CellSpecTxt::DateTime(datetime) => format_duration(time_since(*datetime)),
                CellSpecTxt::Duration(duration) => format_duration(*duration),
                CellSpecTxt::Index => "[index]".to_string(),
                CellSpecTxt::Int(num) => format!("{num}"),
                CellSpecTxt::None => "Unknown/None".to_string(),
                CellSpecTxt::Quantity(quant) => quant.0.clone(),
                CellSpecTxt::Str(s) => s.to_string(),
            }
        )
    }
}

impl<'a> From<&'a str> for CellSpec<'a> {
    fn from(s: &'a str) -> Self {
        CellSpec {
            txt: CellSpecTxt::Str(Cow::Borrowed(s)),
            fg: None,
            bg: None,
            align: None,
        }
    }
}

impl<'a> From<Cow<'a, str>> for CellSpec<'a> {
    fn from(c: Cow<'a, str>) -> Self {
        CellSpec {
            txt: CellSpecTxt::Str(c),
            fg: None,
            bg: None,
            align: None,
        }
    }
}

impl<'a> From<String> for CellSpec<'a> {
    fn from(s: String) -> Self {
        CellSpec {
            txt: CellSpecTxt::Str(Cow::Owned(s)),
            fg: None,
            bg: None,
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
            fg: None,
            bg: None,
            align: None,
        }
    }
}

impl<'a> From<Duration> for CellSpec<'a> {
    fn from(duration: Duration) -> Self {
        CellSpec {
            txt: CellSpecTxt::Duration(duration),
            fg: None,
            bg: None,
            align: None,
        }
    }
}

impl<'a> From<DateTime<Utc>> for CellSpec<'a> {
    fn from(dt: DateTime<Utc>) -> Self {
        CellSpec {
            txt: CellSpecTxt::DateTime(dt),
            fg: None,
            bg: None,
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
                fg: None,
                bg: None,
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

// We ensure they are in sync (see impl for `Ord`), but clippy doesn't seem to recognize this.
#[allow(clippy::non_canonical_partial_ord_impl)]
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
    let mut split = match chars.position(|c| !c.is_ascii_digit()) {
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
        match (suffix[1..]).parse::<u32>() {
            Ok(exp) => {
                let famt = (amt * base10.pow(exp)) as f64;
                if has_neg {
                    return -famt;
                } else {
                    return famt;
                }
            }
            Err(_) => {
                println!("Invalid suffix for quantity: {suffix}");
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
            println!("Invalid suffix for quantity {suffix}");
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
    match matches.get_one::<String>("regex").map(|s| s.as_str()) {
        Some(pattern) => {
            if let Ok(regex) = Regex::new(pattern) {
                Ok(Some(regex))
            } else {
                Err(format!("Invalid regex: {pattern}"))
            }
        }
        None => Ok(None),
    }
}

pub fn print_filled_table(table: &mut comfy_table::Table, writer: &mut ClickWriter) {
    table.load_preset(UTF8_TABLE_STYLE);
    table.set_content_arrangement(comfy_table::ContentArrangement::Dynamic);
    clickwriteln!(writer, "{table}");
}

#[allow(clippy::ptr_arg)]
pub fn print_table<T: Into<comfy_table::Row>>(
    titles: T,
    specs: Vec<Vec<CellSpec<'_>>>,
    env: &Env,
    writer: &mut ClickWriter,
) -> comfy_table::Table {
    let mut table = comfy_table::Table::new();
    table.load_preset(UTF8_TABLE_STYLE);
    table.set_content_arrangement(comfy_table::ContentArrangement::Dynamic);
    table.set_header(titles);
    for (index, t_spec) in specs.iter().enumerate() {
        let row_vec: Vec<Cell> = t_spec.iter().map(|spec| spec.to_cell(index, env)).collect();
        table.add_row(row_vec);
    }
    clickwriteln!(writer, "{table}");
    table
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
