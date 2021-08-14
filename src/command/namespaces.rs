

use clap::{App, Arg};
use crate::env::Env;
use std::io::{stderr, Write};
use rustyline::completion::Pair as RustlinePair;
use crate::output::ClickWriter;
use crate::cmd::{Cmd, exec_match, start_clap};
use std::collections::HashMap;
use std::cell::RefCell;
use ansi_term::Colour::Yellow;
use crate::completer;

use k8s_openapi::api::core::v1 as api;
use k8s_openapi::List;

command!(
    Namespaces,
    "namespaces",
    "Get namespaces in current context",
    |clap: App<'static, 'static>| clap.arg(
        Arg::with_name("regex")
            .short("r")
            .long("regex")
            .help("Filter namespaces by the specified regex")
            .takes_value(true)
    ),
    vec!["namespaces"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, _writer| {
        let _regex = match crate::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let (request, _response_body) = api::Namespace::list_namespace(Default::default()).unwrap();
        let ns_list: List<api::Namespace> = env.run_on_context(|c| {
            Ok(c.execute_list(request).unwrap())
        }).unwrap();
        for ns in ns_list.items {
            println!("{}", ns.metadata.name.unwrap());
        }
        // let nl: Option<NamespaceList> = env.run_on_kluster(|k| k.get("/api/v1/namespaces"));

        // if let Some(l) = nl {
        //     print_namespaces(&l, regex, writer);
        // }
    }
);
