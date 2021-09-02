use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::api::core::v1 as api;
use k8s_openapi::List;
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{handle_list_result, Extractor},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{stderr, Write};

lazy_static! {
    static ref NS_EXTRACTORS: HashMap<String, Extractor<api::Namespace>> = {
        let mut m: HashMap<String, Extractor<api::Namespace>> = HashMap::new();
        m.insert("Status".to_owned(), namespace_status);
        m
    };
}

fn namespace_to_kobj(namespace: &api::Namespace) -> KObj {
    KObj {
        name: namespace
            .metadata
            .name
            .clone()
            .unwrap_or("<Unknown>".into()),
        namespace: None,
        typ: ObjType::Namespace,
    }
}

fn namespace_status<'a>(namespace: &'a api::Namespace) -> Option<CellSpec<'a>> {
    namespace
        .status
        .as_ref()
        .and_then(|stat| stat.phase.as_ref().map(|p| p.as_str().into()))
}

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
    |matches, env, writer| {
        let regex = match crate::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let (request, _response_body) = api::Namespace::list_namespace(Default::default()).unwrap();
        let ns_list_opt: Option<List<api::Namespace>> =
            env.run_on_context(|c| c.execute_list(request));
        handle_list_result(
            env,
            writer,
            vec!["Name", "Age", "Status"],
            ns_list_opt,
            Some(&NS_EXTRACTORS),
            regex,
            None,
            matches.is_present("reverse"),
            namespace_to_kobj,
        );
    }
);
