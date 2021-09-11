use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use chrono::offset::Utc;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::identity,
    completer,
    config,
    env::Env,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{stderr, Write};


command!(
    Clear,
    "clear",
    "Clear the currently selected kubernetes object",
    identity,
    vec!["clear"],
    noop_complete!(),
    no_named_complete!(),
    |_, env, _| {
        env.clear_current();
    }
);

command!(
    EnvCmd,
    "env",
    "Print information about the current environment",
    identity,
    vec!["env"],
    noop_complete!(),
    no_named_complete!(),
    |_matches, env, writer| {
        clickwriteln!(writer, "{}", env);
    }
);

command!(
    Quit,
    "quit",
    "Quit click",
    identity,
    vec!["q", "quit", "exit"],
    noop_complete!(),
    no_named_complete!(),
    |_, env, _| {
        env.quit = true;
    }
);

pub const SET_OPTS: &[&str] = &[
    "completion_type",
    "edit_mode",
    "editor",
    "terminal",
    "range_separator",
];

command!(
    SetCmd,
    "set",
    "Set click options. (See 'help completion' and 'help edit_mode' for more information",
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("option")
                .help("The click option to set")
                .required(true)
                .index(1)
                .possible_values(SET_OPTS),
        )
        .arg(
            Arg::with_name("value")
                .help("The value to set the option to")
                .required(true)
                .index(2),
        )
        .after_help(
            "Note that if your value contains a -, you'll need to tell click it's not an option by
passing '--' before.

Example:
  # Set the range_separator (needs the '--' after set since the value contains a -)
  set -- range_separator \"---- {name} [{namespace}] ----\"

  # set edit_mode
  set edit_mode emacs",
        )
    },
    vec!["set"],
    vec![&completer::setoptions_values_completer],
    no_named_complete!(),
    |matches, env, writer| {
        let option = matches.value_of("option").unwrap(); // safe, required
        let value = matches.value_of("value").unwrap(); // safe, required
        let mut failed = false;
        match option {
            "completion_type" => match value {
                "circular" => env.set_completion_type(config::CompletionType::Circular),
                "list" => env.set_completion_type(config::CompletionType::List),
                _ => {
                    write!(
                        stderr(),
                        "Invalid completion type.  Possible values are: [circular, list]\n"
                    )
                    .unwrap_or(());
                    failed = true;
                }
            },
            "edit_mode" => match value {
                "vi" => env.set_edit_mode(config::EditMode::Vi),
                "emacs" => env.set_edit_mode(config::EditMode::Emacs),
                _ => {
                    write!(
                        stderr(),
                        "Invalid edit_mode.  Possible values are: [emacs, vi]\n"
                    )
                    .unwrap_or(());
                    failed = true;
                }
            },
            "editor" => {
                env.set_editor(Some(value));
            }
            "terminal" => {
                env.set_terminal(Some(value));
            }
            "range_separator" => {
                env.click_config.range_separator = value.to_string();
            }
            _ => {
                // this shouldn't happen
                write!(stderr(), "Invalid option\n").unwrap_or(());
                failed = true;
            }
        }
        if !failed {
            clickwriteln!(writer, "Set {} to '{}'", option, value);
        }
    }
);


command!(
    UtcCmd,
    "utc",
    "Print current time in UTC",
    identity,
    vec!["utc"],
    noop_complete!(),
    no_named_complete!(),
    |_, _, writer| {
        clickwriteln!(writer, "{}", Utc::now());
    }
);
