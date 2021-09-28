use ansi_term::Colour::Yellow;
use chrono::offset::Utc;
use clap::{App, Arg};
use prettytable::Table;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, identity, start_clap, Cmd},
    completer, config,
    env::Env,
    output::ClickWriter,
    table::CellSpec,
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
        Ok(())
    }
);

fn print_contexts(env: &Env, writer: &mut ClickWriter) {
    let mut contexts: Vec<&String> = env.config.contexts.keys().collect();
    contexts.sort();
    let mut table = Table::new();
    table.set_titles(row!["Context", "Api Server Address"]);
    let ctxs = contexts
        .iter()
        .map(|context| {
            let mut row: Vec<CellSpec> = Vec::new();
            let cluster = match env.config.clusters.get(*context) {
                Some(c) => c.server.as_str(),
                None => "[no cluster for context]",
            };
            row.push(CellSpec::with_style((*context).clone().into(), "FR"));
            row.push(cluster.into());
            (context, row)
        })
        .collect();
    table.set_format(*crate::table::TBLFMT);
    crate::table::print_table(&mut table, &ctxs, writer);
}

command!(
    Context,
    "context",
    "Set the current context (will clear any selected pod). \
     With no argument, lists available contexts.",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("context")
            .help("The name of the context")
            .required(false)
            .index(1)
    ),
    vec!["ctx", "context"],
    vec![&completer::context_complete],
    no_named_complete!(),
    |matches, env, writer| {
        if matches.is_present("context") {
            let context = matches.value_of("context");
            if let (&Some(ref k), Some(c)) = (&env.kluster, context) {
                if k.name == c {
                    // no-op if we're already in the specified context
                    return Ok(());
                }
            }
            env.set_context(context);
            env.clear_current();
        } else {
            print_contexts(env, writer);
        }
        Ok(())
    }
);

command!(
    Contexts,
    "contexts",
    "List available contexts",
    identity,
    vec!["contexts", "ctxs"],
    noop_complete!(),
    no_named_complete!(),
    |_, env, writer| {
        print_contexts(env, writer);
        Ok(())
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
        Ok(())
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
        Ok(())
    }
);

command!(
    Range,
    "range",
    "List the objects that are in the currently selected range (see 'help ranges' for general \
     information about ranges)",
    identity,
    vec!["range"],
    noop_complete!(),
    no_named_complete!(),
    |_, env, writer| {
        let mut table = Table::new();
        table.set_titles(row!["Name", "Type", "Namespace"]);
        env.apply_to_selection(writer, None, |obj, _| {
            table.add_row(row!(
                obj.name(),
                obj.type_str(),
                obj.namespace.as_deref().unwrap_or("")
            ));
            Ok(())
        })?;
        crate::table::print_filled_table(&mut table, writer);
        Ok(())
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
        Ok(())
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
        Ok(())
    }
);
