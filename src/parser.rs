//! bash-like cmdline parser

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
                        if arg.len() > 0 || was_quoted || c != ' ' {
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

            if arg.len() > 0 || was_quoted {
                return Some((start..self.cmdline_len, ' ', arg));
            }
        }

        None
    }
}
