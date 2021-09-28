use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    completer,
    env::Env,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

command!(
    Describe,
    "describe",
    "Describe the active kubernetes object.",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the full description in json")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("yaml")
                .short("y")
                .long("yaml")
                .help("Print the full description in yaml")
                .takes_value(false)
        ),
    vec!["describe"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| obj.describe(&matches, env, writer),
        )
    }
);
