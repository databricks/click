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
        let (inclusive, end_str) = if end_str.starts_with("..=") {
            (true, &end_str[3..])
        } else {
            (false, &end_str[2..])
        };
        let start = if start_str.is_empty() {
            0
        } else {
            if let Ok(s) = start_str.parse::<usize>() {
                s
            } else {
                // whatever was before the .. isn't a number, so this isn't a proper range
                return None;
            }
        };

        if end_str.is_empty() {
            if inclusive {
                // invalid range of the form N..=
                return None;
            } else {
                // this is a range from, return the range
                return Some(Box::new(start..));
            }
        } else {
            if let Ok(end) = end_str.parse::<usize>() {
                // also specified an end, return the specified range
                if inclusive {
                    return Some(Box::new(start..=end));
                } else {
                    return Some(Box::new(start..end));
                }
            } else {
                // whatever was after the .. isn't a number, so this isn't a proper range
                return None;
            }
        };
    }
    None
}
