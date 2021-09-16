use ansi_term::{
    Colour::{Green, Red, Yellow},
    Style,
};
use clap::{App, Arg};
use k8s_openapi::api::core::v1 as api;
use k8s_openapi::{List, ListOptional};
use rustyline::completion::Pair as RustlinePair;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{add_extra_cols, handle_list_result, show_arg, sort_arg, Extractor, SortFunc},
    completer,
    env::{Env, ObjectSelection},
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

use std::array::IntoIter;
//use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{stderr, Write};

lazy_static! {
    static ref POD_EXTRACTORS: HashMap<String, Extractor<api::Pod>> = {
        let mut m: HashMap<String, Extractor<api::Pod>> = HashMap::new();
        m.insert("IP".to_owned(), pod_ip);
        m.insert("Labels".to_owned(), pod_labels);
        m.insert("Namespace".to_owned(), pod_namespace);
        m.insert("Node".to_owned(), pod_node);
        m.insert("Nominated Node".to_owned(), pod_nominated_node);
        m.insert("Readiness Gates".to_owned(), pod_readiness_gates);
        m.insert("Ready".to_owned(), ready_counts);
        m.insert("Restarts".to_owned(), restart_count);
        m.insert("Status".to_owned(), pod_status);
        m
    };
    static ref EXTRA_COLS: Vec<(&'static str, &'static str)> = vec![
        ("ip", "IP"),
        ("labels", "Labels"),
        ("namespace", "Namespace"),
        ("node", "Node"),
        ("nominatednode", "Nominated Node"),
        ("readinessgates", "Readiness Gates"),
    ];
}

fn pod_to_kobj(pod: &api::Pod) -> KObj {
    let containers = match &pod.spec {
        Some(spec) => spec
            .containers
            .iter()
            .map(|cont| cont.name.clone())
            .collect(),
        None => vec![],
    };
    let meta = &pod.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::Pod { containers },
    }
}

// Check if a pod has a waiting container
fn has_waiting(pod: &api::Pod) -> bool {
    match pod.status.as_ref().map(|stat| &stat.container_statuses) {
        Some(stats) => {
            stats.iter().any(|cs| {
                match cs.state.as_ref() {
                    Some(state) => {
                        state.waiting.is_some()
                            || (
                                // if all 3 are None, default is waiting
                                state.running.is_none() && state.terminated.is_none()
                            )
                    }
                    None => false,
                }
            })
        }
        None => false,
    }
}

fn phase_style_str(phase: &str) -> &'static str {
    match phase {
        "Running" | "Active" => "Fg",
        "Terminated" | "Terminating" => "Fr",
        "Pending" | "ContainerCreating" => "Fy",
        "Succeeded" => "Fb",
        "Failed" => "Fr",
        "Unknown" => "Fr",
        _ => "Fr",
    }
}

fn pod_ip(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.status
        .as_ref()
        .and_then(|status| status.pod_ip.as_ref().map(|pi| pi.as_str().into()))
}

fn pod_labels(pod: &api::Pod) -> Option<CellSpec<'_>> {
    Some(crate::command::keyval_string(&pod.metadata.labels).into())
}

fn pod_namespace(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.metadata.namespace.as_ref().map(|ns| ns.as_str().into())
}

fn pod_node(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_ref().map(|nn| nn.as_str().into()))
}

fn pod_nominated_node(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.status
        .as_ref()
        .map(|status| match status.nominated_node_name.as_ref() {
            Some(nn) => nn.as_str().into(),
            None => "<none>".into(),
        })
}

// get the number of ready containers and total containers as ready/total
fn ready_counts(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.status.as_ref().map(|stat| {
        let mut count = 0;
        let mut ready = 0;
        for cs in stat.container_statuses.iter() {
            count += 1;
            if cs.ready {
                ready += 1;
            }
        }
        format!("{}/{}", ready, count).into()
    })
}

fn pod_readiness_gates(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.spec.as_ref().map(|spec| {
        if spec.readiness_gates.is_empty() {
            "<none>".into()
        } else {
            let gates: Vec<&str> = spec
                .readiness_gates
                .iter()
                .map(|rg| rg.condition_type.as_str())
                .collect();
            gates.join(", ").into()
        }
    })
}

fn restart_count(pod: &api::Pod) -> Option<CellSpec<'_>> {
    pod.status.as_ref().map(|stat| {
        let count = stat
            .container_statuses
            .iter()
            .fold(0, |acc, cs| acc + cs.restart_count);
        format!("{}", count).into()
    })
}

fn pod_status(pod: &api::Pod) -> Option<CellSpec<'_>> {
    let status = if pod.metadata.deletion_timestamp.is_some() {
        // Was deleted
        "Terminating"
    } else if has_waiting(pod) {
        "ContainerCreating"
    } else {
        pod.status
            .as_ref()
            .and_then(|stat| stat.phase.as_deref())
            .unwrap_or("Unknown")
    };
    let style = phase_style_str(status);
    Some(CellSpec::with_style(status.into(), style))
}

command!(
    Pods,
    "pods",
    "Get pods (in current namespace if set)",
    //&EXTRA_COLS,
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("labels")
                .short("L")
                .long("labels")
                .help("include labels in output (deprecated, use --show labels)")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("node")
                .short("n")
                .long("node")
                .help("Only fetch pods on the specified node.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("regex")
                .short("r")
                .long("regex")
                .help("Filter returned value by the specified regex")
                .takes_value(true),
        )
        .arg(show_arg(
            &EXTRA_COLS
                .iter()
                .map(|(flag, _)| *flag)
                .collect::<Vec<&str>>(),
            true,
        ))
        .arg(sort_arg(
            &["name", "ready", "status", "restarts", "age"],
            Some(
                &EXTRA_COLS
                    .iter()
                    .map(|(flag, _)| *flag)
                    .collect::<Vec<&str>>(),
            ),
        ))
        .arg(
            Arg::with_name("reverse")
                .short("R")
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        )
    },
    vec!["pods"],
    noop_complete!(),
    IntoIter::new([(
        "sort".to_string(),
        completer::pod_sort_values_completer as fn(&str, &Env) -> Vec<RustlinePair>
    )])
    .collect(),
    |matches, env, writer| {
        let regex = match crate::table::get_regex(&matches) {
            Ok(r) => r,
            Err(s) => {
                write!(stderr(), "{}\n", s).unwrap_or(());
                return;
            }
        };

        let mut opts: ListOptional = ListOptional::<'_> {
            label_selector: matches.value_of("label"),
            ..Default::default()
        };
        let mut field_sel = None;
        match matches.value_of("node") {
            Some(nodeval) => {
                field_sel = Some(format!("spec.nodeName={}", nodeval));
            }
            None => {
                if let ObjectSelection::Single(obj) = env.current_selection() {
                    if obj.is(ObjType::Node) {
                        field_sel = Some(format!("spec.nodeName={}", obj.name()));
                    }
                }
            }
        }
        opts.field_selector = field_sel.as_deref();

        let (request, _response_body) = match &env.namespace {
            Some(ns) => api::Pod::list_namespaced_pod(ns, opts).unwrap(),
            None => api::Pod::list_pod_for_all_namespaces(opts).unwrap(),
        };
        let pod_list_opt: Option<List<api::Pod>> = env.run_on_context(|c| c.execute_list(request));

        let mut cols = vec!["Name", "Ready", "Status", "Restarts", "Age"];

        let mut flags: Vec<&str> = match matches.values_of("show") {
            Some(v) => v.collect(),
            None => vec![],
        };

        let sort = matches
            .value_of("sort")
            .map(|s| match s.to_lowercase().as_str() {
                "age" => {
                    let sf = crate::command::PreExtractSort {
                        cmp: crate::command::age_cmp,
                    };
                    SortFunc::Pre(sf)
                }
                "name" => SortFunc::Post("Name"),
                "labels" => {
                    flags.push("labels");
                    SortFunc::Post("Labels")
                }
                "state" => SortFunc::Post("State"),
                "roles" => SortFunc::Post("Roles"),
                "version" => SortFunc::Post("Version"),
                other => {
                    let mut func = None;
                    for (flag, col) in EXTRA_COLS.iter() {
                        if flag.eq(&other) {
                            flags.push(flag);
                            func = Some(SortFunc::Post(col));
                        }
                    }
                    match func {
                        Some(f) => f,
                        None => panic!("Shouldn't be allowed to ask to sort by: {}", other),
                    }
                }
            });

        let specified_show_namespace = flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("namespace"));

        add_extra_cols(&mut cols, matches.is_present("labels"), flags, &EXTRA_COLS);

        // if we're in a namespace, we don't want to add the namespace col
        if env.namespace.is_some() {
            // only remove if we haven't explicitly asked for Namespce
            if !specified_show_namespace {
                let mut i = 0;
                while i < cols.len() {
                    if cols[i] == "Namespace" {
                        cols.remove(i);
                    } else {
                        i += 1;
                    }
                }
            }
        }

        handle_list_result(
            env,
            writer,
            cols,
            pod_list_opt,
            Some(&POD_EXTRACTORS),
            regex,
            sort,
            matches.is_present("reverse"),
            pod_to_kobj,
        );
    }
);

// also add a command to print all the containers of a pod
command!(
    Containers,
    "containers",
    "Print information about the containers of the active pod",
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("volumes")
                .short("v")
                .long("volumes")
                .help("show information about each containers volume mounts")
                .takes_value(false),
        )
    },
    vec!["conts", "containers"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| {
                if obj.is_pod() {
                    print_containers(obj, env, matches.is_present("volumes"), writer);
                } else {
                    clickwriteln!(writer, "containers only possible on a Pod");
                }
            },
        );
    }
);

// conainer helper commands
fn print_containers(obj: &KObj, env: &Env, volumes: bool, writer: &mut ClickWriter) {
    let (request, _) = api::Pod::read_namespaced_pod(
        obj.name(),
        obj.namespace.as_ref().unwrap(),
        Default::default(),
    )
    .unwrap();
    match env
        .run_on_context(|c| c.read::<api::ReadNamespacedPodResponse>(request))
        .unwrap()
    {
        api::ReadNamespacedPodResponse::Ok(pod) => match pod.status {
            Some(status) => {
                for cont in status.container_statuses.iter() {
                    clickwrite!(writer, "Name:\t{}\n", Style::new().bold().paint(&cont.name));
                    clickwrite!(
                        writer,
                        "  ID:\t\t{}\n",
                        cont.container_id.as_deref().unwrap_or("<none>")
                    );
                    clickwrite!(writer, "  Image:\t{}\n", cont.image_id);
                    print_state_string(&cont.state, writer);
                    clickwrite!(writer, "  Ready:\t{}\n", cont.ready);
                    clickwrite!(writer, "  Restarts:\t{}\n", cont.restart_count);

                    // find the spec for this container
                    if let Some(spec) = pod.spec.as_ref() {
                        let cont_spec = spec.containers.iter().find(|cs| cs.name == cont.name);
                        if let Some(cont_spec) = cont_spec {
                            // print resources
                            clickwrite!(writer, "  Resources:\n");
                            match cont_spec.resources.as_ref() {
                                Some(resources) => {
                                    clickwrite!(writer, "    Requests:\n");
                                    for (resource, quant) in resources.requests.iter() {
                                        clickwrite!(writer, "      {}:\t{}\n", resource, quant.0)
                                    }
                                    if resources.requests.is_empty() {
                                        clickwrite!(writer, "      <none>\n");
                                    }
                                    clickwrite!(writer, "    Limits:\n");
                                    for (resource, quant) in resources.limits.iter() {
                                        clickwrite!(writer, "      {}:\t{}\n", resource, quant.0)
                                    }
                                    if resources.limits.is_empty() {
                                        clickwrite!(writer, "      <none>\n");
                                    }
                                }
                                None => {
                                    clickwrite!(writer, "    <Unknown>\n");
                                }
                            }

                            if volumes {
                                // print volumes
                                clickwrite!(writer, "  Volumes:\n");
                                if !cont_spec.volume_mounts.is_empty() {
                                    for vol in cont_spec.volume_mounts.iter() {
                                        clickwrite!(writer, "   {}\n", vol.name);
                                        clickwrite!(writer, "    Path:\t{}\n", vol.mount_path);
                                        clickwrite!(
                                            writer,
                                            "    Sub-Path:\t{}\n",
                                            vol.sub_path.as_deref().unwrap_or("<none>")
                                        );
                                        clickwrite!(
                                            writer,
                                            "    Read-Only:\t{}\n",
                                            vol.read_only.unwrap_or(false)
                                        );
                                    }
                                } else {
                                    clickwrite!(writer, "    No Volumes\n");
                                }
                            }
                        }
                    }

                    clickwrite!(writer, "\n");
                }
            }
            None => {
                clickwrite!(writer, "No container info returned from api server\n");
            }
        },
        api::ReadNamespacedPodResponse::Other(o) => {
            clickwrite!(writer, "Error getting pod info: {:?}\n", o);
        }
    }
}

fn print_state_string(state: &Option<api::ContainerState>, writer: &mut ClickWriter) {
    clickwrite!(writer, "  State:\t");
    match state {
        Some(state) => {
            if let Some(running) = state.running.as_ref() {
                clickwrite!(writer, "{}\n", Green.paint("Running"));
                match &running.started_at {
                    Some(start) => clickwrite!(writer, "\t\t  started at: {}\n", start.0),
                    None => clickwrite!(writer, "\t\t  since unknown\n"),
                }
            } else if let Some(terminated) = state.terminated.as_ref() {
                let message = terminated.message.as_deref().unwrap_or("no message");
                let reason = terminated.reason.as_deref().unwrap_or("no reason");
                let tsr = terminated
                    .finished_at
                    .as_ref()
                    .map(|fa| fa.0.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                clickwrite!(writer, "{}\n", Red.paint("Terminated"));
                clickwrite!(writer, "\t\t  at: {}\n", tsr);
                clickwrite!(writer, "\t\t  code: {}\n", terminated.exit_code);
                clickwrite!(writer, "\t\t  message: {}\n", message);
                clickwrite!(writer, "\t\t  reason: {}\n", reason);
            } else if let Some(waiting) = state.waiting.as_ref() {
                let message = waiting.message.as_deref().unwrap_or("no message");
                let reason = waiting.reason.as_deref().unwrap_or("no reason");
                clickwrite!(writer, "{}\n", Yellow.paint("Waiting"));
                clickwrite!(writer, "\t\t  message: {}\n", message);
                clickwrite!(writer, "\t\t  reason: {}\n", reason);
            } else {
                clickwrite!(
                    writer,
                    "{}",
                    format!("{} (reason unknown)\n", Yellow.paint("Waiting"))
                );
            }
        }
        None => clickwrite!(writer, "Unknown"),
    }
}
