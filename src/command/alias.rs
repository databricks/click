use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    completer, config,
    env::Env,
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

command!(
    Alias,
    "alias",
    "Define or display aliases",
    |clap: App<'static, 'static>| clap
        .arg(
            Arg::with_name("alias")
                .help(
                    "the short version of the command.\nCannot be 'alias', 'unalias', or a number."
                )
                .validator(|s: String| {
                    if s == "alias" || s == "unalias" || s.parse::<usize>().is_ok() {
                        Err("alias cannot be \"alias\", \"unalias\", or a number".to_owned())
                    } else {
                        Ok(())
                    }
                })
                .required(false)
                .requires("expanded")
        )
        .arg(
            Arg::with_name("expanded")
                .help("what the short version of the command should expand to")
                .required(false)
                .requires("alias")
        )
        .after_help(
            "An alias is a substitution rule.  When click encounters an alias at the start of a
command, it will substitue the expanded version for what was typed.

As with Bash: The first word of the expansion is tested for aliases, but a word that is identical to
an alias being expanded is not expanded a second time.  So one can alias logs to \"logs -e\", for
instance, without causing infinite expansion.

Examples:
  # Display current aliases
  alias

  # alias p to pods
  alias p pods

  # alias pn to get pods with nginx in the name
  alias pn \"pods -r nginx\"

  # alias el to run logs and grep for ERROR
  alias el \"logs | grep ERROR\""
        ),
    vec!["alias", "aliases"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        if matches.is_present("alias") {
            let alias = matches.value_of("alias").unwrap(); // safe, checked above
            let expanded = matches.value_of("expanded").unwrap(); // safe, required with alias
            env.add_alias(config::Alias {
                alias: alias.to_owned(),
                expanded: expanded.to_owned(),
            });
            clickwriteln!(writer, "aliased {} = '{}'", alias, expanded);
        } else {
            for alias in env.click_config.aliases.iter() {
                clickwriteln!(writer, "alias {} = '{}'", alias.alias, alias.expanded);
            }
        }
    }
);

command!(
    Unalias,
    "unalias",
    "Remove an alias",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("alias")
            .help("Short version of alias to remove")
            .required(true)
    ),
    vec!["unalias"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let alias = matches.value_of("alias").unwrap(); // safe, required
        if env.remove_alias(alias) {
            clickwriteln!(writer, "unaliased: {}", alias);
        } else {
            clickwriteln!(writer, "no such alias: {}", alias);
        }
    }
);
