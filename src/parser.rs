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

//! file to hold parsers for the various things we need to parse ourselves

// This is take and modified from:
// https://github.com/klemens/cmdline-parser/blob/master/src/unix.rs

use std::iter::Peekable;
use std::ops::Range;
use std::str::CharIndices;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ParsingState {
    Normal,
    Escaped,
    SingleQuoted,
    DoubleQuoted,
    DoubleQuotedEscaped,
}

/// Parser for bash-like command lines.
///
/// Supports parsing arguments which use escaping, single quotes and double
/// quotes (no expansion of `$` etc.). Splits on spaces by default.
///
/// Unfinished quotings at the end of a command line are parsed successfully
/// to support building of e.g. path completers.
// TODO: Rename to BashParser
pub struct Parser<'a> {
    state: ParsingState,
    cmdline: Peekable<CharIndices<'a>>,
    cmdline_len: usize,
}

impl<'a> Parser<'a> {
    pub fn new(cmdline: &str) -> Parser {
        Parser {
            state: ParsingState::Normal,
            cmdline: cmdline.char_indices().peekable(),
            cmdline_len: cmdline.len(),
        }
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = (Range<usize>, char, String);

    fn next(&mut self) -> Option<Self::Item> {
        use self::ParsingState::*;

        let mut arg = String::new();

        if let Some(&(mut start, _)) = self.cmdline.peek() {
            let mut yield_value = false;
            let mut was_quoted = false;

            for (i, c) in &mut self.cmdline {
                self.state = match (self.state, c) {
                    (Normal, '\\') => Escaped,
                    (Normal, '\'') => SingleQuoted,
                    (Normal, '"') => DoubleQuoted,
                    (Normal, c) if c == ' ' || c == '|' || c == '>' => {
                        if !arg.is_empty() || was_quoted || c != ' ' {
                            yield_value = true;
                        } else {
                            start = i + 1;
                        }
                        Normal
                    }
                    (Normal, _) | (Escaped, _) => {
                        arg.push(c);
                        Normal
                    }
                    (SingleQuoted, '\'') => {
                        was_quoted = true;
                        Normal
                    }
                    (SingleQuoted, _) => {
                        arg.push(c);
                        SingleQuoted
                    }
                    (DoubleQuoted, '"') => {
                        was_quoted = true;
                        Normal
                    }
                    (DoubleQuoted, '\\') => DoubleQuotedEscaped,
                    (DoubleQuoted, _)
                    | (DoubleQuotedEscaped, '"')
                    | (DoubleQuotedEscaped, '\\') => {
                        arg.push(c);
                        DoubleQuoted
                    }
                    (DoubleQuotedEscaped, _) => {
                        arg.push('\\');
                        arg.push(c);
                        DoubleQuoted
                    }
                };

                if yield_value {
                    return Some((start..i, c, arg));
                }
            }

            if !arg.is_empty() || was_quoted {
                return Some((start..self.cmdline_len, ' ', arg));
            }
        }

        None
    }
}

/// Try and parse a line of the form [N]..[M]. These conform to Rust's range expressions:
/// https://doc.rust-lang.org/reference/expressions/range-expr.html
/// If we parse this successfully, we return
pub fn try_parse_range(line: &str) -> Option<Box<dyn Iterator<Item = usize>>> {
    if let Some(idx) = line.find("..") {
        // we have a string with a .., so keep processing
        let (start_str, end_str) = line.split_at(idx);
        let (inclusive, end_str) = if let Some(rest) = end_str.strip_prefix("..=") {
            (true, rest)
        } else {
            (false, &end_str[2..])
        };
        let start = if start_str.is_empty() {
            0
        } else if let Ok(s) = start_str.parse::<usize>() {
            s
        } else {
            // whatever was before the .. isn't a number, so this isn't a proper range
            return None;
        };

        if end_str.is_empty() {
            if inclusive {
                // invalid range of the form N..=
                return None;
            } else {
                // this is a range from, return the range
                return Some(Box::new(start..));
            }
        } else if let Ok(end) = end_str.parse::<usize>() {
            // also specified an end, return the specified range
            if inclusive {
                return Some(Box::new(start..=end));
            } else {
                return Some(Box::new(start..end));
            }
        } else {
            // whatever was after the .. isn't a number, so this isn't a proper range
            return None;
        };
    }
    None
}

/// try and parse a line of comma separated numbers like 1,3,5
pub fn try_parse_csl(line: &str) -> Option<Box<dyn Iterator<Item = usize>>> {
    let mut ret = Vec::new();
    let l = line.trim();
    if l.is_empty() {
        return None;
    }
    for item in l.split_terminator(',') {
        match item.trim().parse::<usize>() {
            Ok(num) => ret.push(num),
            Err(_) => return None, // fail as soon as something's not a usize
        }
    }
    Some(Box::new(ret.into_iter()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_parse_csl_test() {
        let v: Vec<usize> = try_parse_csl("1,2,3").unwrap().collect();
        assert_eq!(vec!(1, 2, 3), v);

        let v: Vec<usize> = try_parse_csl("1, 2, 3").unwrap().collect();
        assert_eq!(vec!(1, 2, 3), v);

        let v: Vec<usize> = try_parse_csl("1,   7,   3,").unwrap().collect();
        assert_eq!(vec!(1, 7, 3), v);

        let v: Vec<usize> = try_parse_csl("1,   7,   3,  ").unwrap().collect();
        assert_eq!(vec!(1, 7, 3), v);

        let v: Vec<usize> = try_parse_csl("1").unwrap().collect();
        assert_eq!(vec!(1), v);

        assert!(try_parse_csl("1,x,2").is_none());
        assert!(try_parse_csl("pods").is_none());
        assert!(try_parse_csl("").is_none());
        assert!(try_parse_csl(",").is_none());
        assert!(try_parse_csl("1,,2").is_none());
        assert!(try_parse_csl(",,,").is_none());
        assert!(try_parse_csl(",1,2,").is_none());
    }

    #[test]
    fn try_parse_range_test() {
        let v: Vec<usize> = try_parse_range("1..3").unwrap().collect();
        assert_eq!(vec!(1, 2), v);

        let v: Vec<usize> = try_parse_range("1..=3").unwrap().collect();
        assert_eq!(vec!(1, 2, 3), v);

        let v: Vec<usize> = try_parse_range("..4").unwrap().collect();
        assert_eq!(vec!(0, 1, 2, 3), v);

        let v: Vec<usize> = try_parse_range("6..4").unwrap().collect();
        assert!(v.is_empty());

        let v: Vec<usize> = try_parse_range("6..=6").unwrap().collect();
        assert_eq!(vec!(6), v);

        let mut r = try_parse_range("3..").unwrap();
        for i in 3..10 {
            assert_eq!(r.next().unwrap(), i);
        }

        let mut r = try_parse_range("..").unwrap();
        for i in 0..10 {
            assert_eq!(r.next().unwrap(), i);
        }

        assert!(try_parse_range(",1,2,").is_none());
        assert!(try_parse_range("1").is_none());
        assert!(try_parse_range("pods").is_none());
        assert!(try_parse_range("1.2").is_none());
        assert!(try_parse_range("1..==2").is_none());
        assert!(try_parse_range("").is_none());
        assert!(try_parse_range("   1..=2").is_none());
    }
}
