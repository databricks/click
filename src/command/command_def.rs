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

use clap::builder::{PossibleValue, PossibleValuesParser};
/// This module contains shared code that's useful for defining commands
use clap::{Arg, ArgMatches, Command as ClapCommand};
use rustyline::completion::Pair as RustlinePair;

use crate::env::Env;
use crate::error::ClickError;
use crate::output::ClickWriter;

use std::cell::RefCell;
use std::io::Write;

// command definition
/// Just return what we're given.  Useful for no-op closures in
/// command! macro invocation
pub fn identity<T>(t: T) -> T {
    t
}

pub fn try_complete_all(prefix: &str, cols: &[&str], extra_cols: &[&str]) -> Vec<RustlinePair> {
    let mut v = vec![];
    for val in cols.iter().chain(extra_cols.iter()) {
        if let Some(rest) = val.strip_prefix(prefix) {
            v.push(RustlinePair {
                display: val.to_string(),
                replacement: rest.to_string(),
            });
        }
    }
    v
}

pub fn try_complete(prefix: &str, extra_cols: &[&str], include_all: bool) -> Vec<RustlinePair> {
    let mut v = vec![];
    if include_all {
        if let Some(rest) = "all".strip_prefix(prefix) {
            v.push(RustlinePair {
                display: "all".to_string(),
                replacement: rest.to_string(),
            });
        }
    }
    for val in extra_cols.iter() {
        if let Some(rest) = val.strip_prefix(prefix) {
            v.push(RustlinePair {
                display: val.to_string(),
                replacement: rest.to_string(),
            });
        }
    }
    v
}

macro_rules! extract_first {
    ($map: ident) => {{
        let mut result: [&str; $map.len()] = [""; $map.len()];
        let mut i = 0;
        while i < $map.len() {
            result[i] = $map[i].0;
            i += 1;
        }
        result
    }};
}

const DEFAULT_HELP_TEMPLATE: &str = "\
    {bin} {version}\n\
    {about-with-newline}\n\
    \n\
    {before-help}\
    {usage-heading}\n    {usage}\n\
    \n\
    {all-args}{after-help}\
";

pub trait Cmd {
    // break if returns true
    fn exec(
        &self,
        env: &mut Env,
        args: &mut dyn Iterator<Item = &str>,
        writer: &mut ClickWriter,
    ) -> Result<(), ClickError>;
    fn is(&self, l: &str) -> bool;
    fn get_name(&self) -> &'static str;
    fn try_complete(&self, index: usize, prefix: &str, env: &Env) -> Vec<RustlinePair>;
    fn try_completed_named(
        &self,
        index: usize,
        opt: &str,
        prefix: &str,
        env: &Env,
    ) -> Vec<RustlinePair>;
    fn complete_option(&self, prefix: &str) -> Vec<RustlinePair>;
    fn write_help(&self, writer: &mut ClickWriter);
    fn about(&self) -> &'static str;
}

/// Get the start of a clap object
pub fn start_clap(
    name: &'static str,
    about: &'static str,
    aliases: &'static str,
    trailing_var_arg: bool,
) -> ClapCommand<'static> {
    let app = ClapCommand::new(name)
        .about(about)
        .before_help(aliases)
        .help_template(DEFAULT_HELP_TEMPLATE)
        .disable_version_flag(true)
        .no_binary_name(true);
    if trailing_var_arg {
        app.trailing_var_arg(true)
    } else {
        app
    }
}

/// Run specified closure with given matches. Returns () on success, or an Err if an error occurs
pub fn exec_match<F>(
    clap: &RefCell<ClapCommand<'static>>,
    env: &mut Env,
    args: &mut dyn Iterator<Item = &str>,
    writer: &mut ClickWriter,
    func: F,
) -> Result<(), ClickError>
where
    F: FnOnce(ArgMatches, &mut Env, &mut ClickWriter) -> Result<(), ClickError>,
{
    let mut cmd = clap.borrow_mut();
    let matches = cmd.try_get_matches_from_mut(args);
    match matches {
        Ok(matches) => func(matches, env, writer),
        Err(e) => {
            if e.kind() == clap::ErrorKind::DisplayHelp {
                cmd.print_help().expect("Couldn't print help");
                // todo: switch back in the same way as write_help
                //clickwriteln!(writer, "{}", e);
                Ok(())
            } else if e.kind() == clap::ErrorKind::DisplayVersion {
                clickwriteln!(writer, "{}", e);
                Ok(())
            } else {
                Err(ClickError::Clap(e))
            }
        }
    }
}

macro_rules! noop_complete {
    () => {
        vec![]
    };
}

macro_rules! no_named_complete {
    () => {
        HashMap::new()
    };
}

/// Macro for defining a command
///
/// # Args
/// * cmd_name: the name of the struct for the command
/// * name: the string name of the command
/// * about: an about string describing the command
/// * extra_args: closure taking a Command that addes any additional argument stuff and returns a Command
/// * aliases: a vector of strs that specify what a user can type to invoke this command
/// * cmplt_expr: an expression to return possible completions for the command
/// * named_cmplters: a map of argument -> completer for completing named arguments
/// * cmd_expr: a closure taking matches, env, and writer that runs to execute the command
/// * trailing_var_arg: set the "TrailingVarArg" setting for clap (see clap docs, default false)
///
/// # Example
/// ```
/// # #[macro_use] extern crate click;
/// # fn main() {
/// command!(Quit,
///         "quit",
///         "Quit click",
///         identity,
///         vec!["q", "quit", "exit"],
///         noop_complete!(),
///         no_named_complete!(),
///         |matches, env, writer| {env.quit = true;}
/// );
/// # }
/// ```
macro_rules! command {
    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $aliases:expr, $cmplters: expr,
     $named_cmplters: expr, $cmd_expr:expr) => {
        command!(
            $cmd_name,
            $name,
            $about,
            $extra_args,
            $aliases,
            $cmplters,
            $named_cmplters,
            $cmd_expr,
            false
        );
    };

    ($cmd_name:ident, $name:expr, $about:expr, $extra_args:expr, $aliases:expr, $cmplters: expr,
     $named_cmplters: expr, $cmd_expr:expr, $trailing_var_arg: expr) => {
        pub struct $cmd_name {
            aliases: Vec<&'static str>,
            clap: RefCell<ClapCommand<'static>>,
            completers: Vec<&'static dyn Fn(&str, &Env) -> Vec<RustlinePair>>,
            named_completers: HashMap<String, fn(&str, &Env) -> Vec<RustlinePair>>,
        }

        impl $cmd_name {
            pub fn new() -> $cmd_name {
                use crossterm::style::Stylize;
                lazy_static! {
                    static ref ALIASES_STR: String =
                        format!("{}:\n    {:?}", "ALIASES".yellow(), $aliases);
                }
                let clap = start_clap($name, $about, &ALIASES_STR, $trailing_var_arg);
                #[allow(clippy::redundant_closure_call)]
                let extra = $extra_args(clap);
                $cmd_name {
                    aliases: $aliases,
                    clap: RefCell::new(extra),
                    completers: $cmplters,
                    named_completers: $named_cmplters,
                }
            }
        }

        impl Cmd for $cmd_name {
            fn exec(
                &self,
                env: &mut Env,
                args: &mut dyn Iterator<Item = &str>,
                writer: &mut ClickWriter,
            ) -> Result<(), crate::error::ClickError> {
                exec_match(&self.clap, env, args, writer, $cmd_expr)
            }

            fn is(&self, l: &str) -> bool {
                self.aliases.contains(&l)
            }

            fn get_name(&self) -> &'static str {
                $name
            }

            // TODO: switch back to command.write_help when
            // https://github.com/clap-rs/clap/issues/3480 is resolved
            fn write_help(&self, writer: &mut ClickWriter) {
                if let Err(res) = self.clap.borrow_mut().print_help() {
                    clickwriteln!(writer, "Couldn't print help: {}", res);
                }
            }

            fn about(&self) -> &'static str {
                $about
            }

            fn try_complete(&self, index: usize, prefix: &str, env: &Env) -> Vec<RustlinePair> {
                match self.completers.get(index) {
                    Some(completer) => completer(prefix, env),
                    None => vec![],
                }
            }

            fn try_completed_named(
                &self,
                index: usize,
                opt: &str,
                prefix: &str,
                env: &Env,
            ) -> Vec<RustlinePair> {
                let app = self.clap.borrow();
                let mut args = app.get_arguments();
                // see if an opt we have matches what we've typed so far
                let arg_opt = args.find(|arg| {
                    // first see if the long flag matches
                    if let Some(long) = arg.get_long() {
                        if long == &opt[2..] {
                            // strip off -- prefix we get passed
                            return true;
                        }
                    }
                    // didn't find a long opt, let's see if a short one matches
                    if opt.len() == 2 {
                        if let Some(short) = arg.get_short() {
                            // safe, strip off - prefix we get passed
                            if (short == opt.chars().nth(1).unwrap()) {
                                return true;
                            }
                        }
                    }
                    false
                });
                match arg_opt {
                    Some(arg) => match self
                        .named_completers
                        .get(arg.get_long().unwrap_or_else(|| ""))
                    {
                        Some(completer) => completer(prefix, env),
                        None => vec![],
                    },
                    None => self.try_complete(index, prefix, env),
                }
            }

            /**
             *  Completes all possible long options for this command, with the given prefix.
             *  This is rather gross as we have to do everything inside this method.
             *  clap::arg is private, so we can't define methods that take the traits
             *  that all args implement, and have to handle each individually
             */
            fn complete_option(&self, prefix: &str) -> Vec<RustlinePair> {
                let repoff = prefix.len();
                let app = self.clap.borrow();
                let args = app.get_arguments();
                args.filter(|arg| completer::long_matches(&arg.get_long(), prefix))
                    .map(|arg| {
                        RustlinePair {
                            display: format!("--{}", arg.get_long().unwrap()), // safe, checked above
                            replacement: format!(
                                "{} ",
                                arg.get_long().unwrap()[repoff..].to_string()
                            ),
                        }
                    })
                    .collect()
            }
        }
    };
}

/// convenience macro for commands that list things (pods, nodes, statefulsets, etc). this macro
/// adds the common various sorting/showing arguments and completors and then calls the base command
/// macro
macro_rules! list_command {
    ($cmd_name:ident, $name:expr, $about:expr, $cols: expr, $extra_cols:expr, $extra_args:expr,
     $aliases:expr, $cmplters: expr, $named_cmplters: expr, $cmd_expr:expr) => {
        mod list_sort_completers {
            use crate::{command::command_def::try_complete_all, env::Env};
            use rustyline::completion::Pair as RustlinePair;
            #[allow(non_snake_case)]
            pub fn $cmd_name(prefix: &str, _env: &Env) -> Vec<RustlinePair> {
                try_complete_all(prefix, $cols, $extra_cols)
            }
        }

        mod list_show_completers {
            use crate::{command::command_def::try_complete, env::Env};
            use rustyline::completion::Pair as RustlinePair;
            #[allow(non_snake_case)]
            pub fn $cmd_name(prefix: &str, _env: &Env) -> Vec<RustlinePair> {
                try_complete(prefix, $extra_cols, true)
            }
        }

        use rustyline::completion::Pair as RustlinePair;
        command!(
            $cmd_name,
            $name,
            $about,
            $extra_args,
            $aliases,
            $cmplters,
            //$named_cmplters,
            [
                (
                    "sort".to_string(),
                    list_sort_completers::$cmd_name as fn(&str, &Env) -> Vec<RustlinePair>
                ),
                (
                    "show".to_string(),
                    list_show_completers::$cmd_name as fn(&str, &Env) -> Vec<RustlinePair>
                )
            ]
            .into_iter()
            .chain($named_cmplters)
            .collect(),
            $cmd_expr,
            false
        );
    };
}

// utility methods for show/sort args

/// Add any specified extra columns
///
/// cols: the vector of columes to show. Any flags to show extra columns will cause the column name
/// to be added to this vector
/// lables: If the --lables flag was specified (deprecated)
/// flags: A vector of the flags that were passed by the user
/// extra_cols: Extra cols to consider. This is a vector of (column_name, flag). If flag is in
/// flags, then column_name is added to cols. The order in this vector is the order columns will be
/// displayed in the output
pub fn add_extra_cols<'a>(
    cols: &mut Vec<&'a str>,
    labels: bool,
    flags: Vec<&str>,
    extra_cols: &[(&'a str, &'a str)],
) {
    let show_all = flags.iter().any(|e| e.eq_ignore_ascii_case("all"));

    for (flag, col) in extra_cols.iter() {
        if col.eq(&"Labels") {
            if labels || flags.iter().any(|e| e.eq_ignore_ascii_case("labels")) {
                cols.push(col)
            }
        } else if show_all || flags.iter().any(|e| e.eq_ignore_ascii_case(flag)) {
            cols.push(col)
        }
    }
}

// fn get_value_parser(set1: &[&str], set2: &[&str]) -> ValueParser {

// }

// sort based on column index given
pub struct SortCol(pub &'static str);

/// get a clap arg for sorting. this takes one or two lists of possible values to allow for passing
/// normal and extra cols
pub fn sort_arg<'a>(cols: &'a [&'static str], extra_cols: Option<&'a [&'static str]>) -> Arg<'a> {
    let pvp = match extra_cols {
        Some(extra) => PossibleValuesParser::new(
            cols.iter()
                .chain(extra.iter())
                .map(|s| PossibleValue::new(s)),
        ),
        None => PossibleValuesParser::new(cols.iter().map(|s| PossibleValue::new(s))),
    };
    Arg::new("sort")
        .short('s')
        .long("sort")
        .help(
            "Sort by specified column (if column isn't shown by default, it will \
             be shown)",
        )
        .takes_value(true)
        .ignore_case(true)
        .value_parser(pvp)
}

static SHOW_HELP: &str =
    "Comma separated list (case-insensitive) of extra columns to show in output. \
     Use '--show all' to show all available columns.";
static SHOW_HELP_WITH_LABELS: &str =
    "Comma separated list (case-insensitive) of extra columns to show in output. \
     Use '--show all,labels' to show all available columns. (Note that 'all' doesn't \
     include labels due to their size)";
/// get a clap arg for showing extra cols.
pub fn show_arg<'a>(extra_cols: &'a [&'static str], labels: bool) -> Arg<'a> {
    let pvp = PossibleValuesParser::new(
        extra_cols
            .iter()
            .chain(["all"].iter())
            .map(|s| PossibleValue::new(s)),
    );
    let arg = Arg::new("show")
        .short('S')
        .long("show")
        .takes_value(true)
        .value_parser(pvp)
        .ignore_case(true)
        .use_value_delimiter(true);
    if labels {
        arg.help(SHOW_HELP_WITH_LABELS)
    } else {
        arg.help(SHOW_HELP)
    }
}
