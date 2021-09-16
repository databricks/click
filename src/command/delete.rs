use ansi_term::Colour::Yellow;
use clap::{App, Arg};
use k8s_openapi::{
    api::apps::v1 as apps_api, api::batch::v1 as batch_api, api::core::v1 as api, http::Request,
    DeleteOptional, DeleteResponse,
};
use rustyline::completion::Pair as RustlinePair;
use serde::de::DeserializeOwned;

use crate::{
    cmd::{exec_match, start_clap, Cmd},
    command::{uppercase_first, valid_u32},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    values::val_str,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, stderr, Write};

fn send_delete<D: DeserializeOwned + Debug>(
    env: &Env,
    writer: &mut ClickWriter,
    request: Request<Vec<u8>>,
) {
    let res: Option<DeleteResponse<D>> = env.run_on_context(|c| c.read(request));
    if let Some(r) = res {
        match r {
            DeleteResponse::OkStatus(_) | DeleteResponse::OkValue(_) => {
                clickwriteln!(writer, "Deleted")
            }
            DeleteResponse::Accepted(_) => clickwriteln!(writer, "Delete request accepted"),
            DeleteResponse::Other(res) => match res {
                Ok(valopt) => match valopt {
                    Some(val) => {
                        clickwriteln!(
                            writer,
                            "Delete request failed. Message: {}",
                            val_str("/message", &val, "<No message>")
                        )
                    }
                    None => {
                        clickwriteln!(writer, "Delete request failed with no reason given");
                    }
                },
                Err(e) => {
                    clickwriteln!(writer, "Delete request failed with an error: {}", e);
                }
            },
        }
    }
}

fn delete_obj(env: &Env, writer: &mut ClickWriter, obj: &KObj, options: DeleteOptional) {
    match obj.namespace.as_ref() {
        Some(ns) => match obj.typ {
            ObjType::ConfigMap => {
                let req = api::ConfigMap::delete_namespaced_config_map(
                    obj.name.as_str(),
                    ns.as_str(),
                    options,
                )
                .unwrap()
                .0;
                send_delete::<api::ConfigMap>(env, writer, req);
            }
            ObjType::Deployment => {
                let req = apps_api::Deployment::delete_namespaced_deployment(
                    obj.name.as_str(),
                    ns.as_str(),
                    options,
                )
                .unwrap()
                .0;
                send_delete::<apps_api::Deployment>(env, writer, req);
            }
            ObjType::Job => {
                let req =
                    batch_api::Job::delete_namespaced_job(obj.name.as_str(), ns.as_str(), options)
                        .unwrap()
                        .0;
                send_delete::<batch_api::Job>(env, writer, req);
            }
            ObjType::Namespace => {
                clickwriteln!(
                    writer,
                    "Namespace has unexpected namespace. Please file an issue on github. \
                     Deleting anyway"
                );
                let req = api::Namespace::delete_namespace(obj.name.as_str(), options)
                    .unwrap()
                    .0;
                send_delete::<api::Namespace>(env, writer, req);
            }
            ObjType::Node => {
                clickwriteln!(
                    writer,
                    "Node has unexpected namespace. Please file an issue on github. \
                         Deleting anyway"
                );
                let req = api::Node::delete_node(obj.name.as_str(), options)
                    .unwrap()
                    .0;
                send_delete::<api::Node>(env, writer, req);
            }
            ObjType::PersistentVolume => {
                clickwriteln!(
                    writer,
                    "PersistentVolume has unexpected namespace. Please file an issue on github. \
                     Deleting anyway"
                );
                let req =
                    api::PersistentVolume::delete_persistent_volume(obj.name.as_str(), options)
                        .unwrap()
                        .0;
                send_delete::<api::PersistentVolume>(env, writer, req);
            }
            ObjType::Pod { .. } => {
                let req = api::Pod::delete_namespaced_pod(obj.name.as_str(), ns.as_str(), options)
                    .unwrap()
                    .0;
                send_delete::<api::Pod>(env, writer, req);
            }
            ObjType::ReplicaSet => {
                let req = apps_api::ReplicaSet::delete_namespaced_replica_set(
                    obj.name.as_str(),
                    ns.as_str(),
                    options,
                )
                .unwrap()
                .0;
                send_delete::<apps_api::ReplicaSet>(env, writer, req);
            }
            ObjType::StatefulSet => {
                let req = apps_api::StatefulSet::delete_namespaced_stateful_set(
                    obj.name.as_str(),
                    ns.as_str(),
                    options,
                )
                .unwrap()
                .0;
                send_delete::<apps_api::StatefulSet>(env, writer, req);
            }
            ObjType::Secret => {
                let req =
                    api::Secret::delete_namespaced_secret(obj.name.as_str(), ns.as_str(), options)
                        .unwrap()
                        .0;
                send_delete::<api::Secret>(env, writer, req);
            }
            ObjType::Service => {
                let req = api::Service::delete_namespaced_service(
                    obj.name.as_str(),
                    ns.as_str(),
                    options,
                )
                .unwrap()
                .0;
                send_delete::<api::Service>(env, writer, req);
            }
        },
        None => match obj.typ {
            ObjType::Node => {
                let req = api::Node::delete_node(obj.name.as_str(), options)
                    .unwrap()
                    .0;
                send_delete::<api::Node>(env, writer, req);
            }
            ObjType::Namespace => {
                let req = api::Namespace::delete_namespace(obj.name.as_str(), options)
                    .unwrap()
                    .0;
                send_delete::<api::Namespace>(env, writer, req);
            }
            ObjType::PersistentVolume => {
                let req =
                    api::PersistentVolume::delete_persistent_volume(obj.name.as_str(), options)
                        .unwrap()
                        .0;
                send_delete::<api::PersistentVolume>(env, writer, req);
            }
            _ => {
                clickwriteln!(
                    writer,
                    "Object {} has no namespace. Cannot delete",
                    obj.name()
                );
            }
        },
    };
}

fn confirm_delete(env: &Env, obj: &KObj, options: DeleteOptional, writer: &mut ClickWriter) {
    let name = obj.name();
    clickwrite!(writer, "Delete {} {} [y/N]? ", obj.type_str(), name);
    io::stdout().flush().expect("Could not flush stdout");
    let mut conf = String::new();
    if io::stdin().read_line(&mut conf).is_ok() {
        if conf.trim() == "y" || conf.trim() == "yes" {
            delete_obj(env, writer, obj, options);
        } else {
            clickwriteln!(writer, "Not deleting");
        }
    } else {
        writeln!(stderr(), "Could not read response, not deleting.").unwrap_or(());
    }
}

command!(
    Delete,
    "delete",
    "Delete the active object (will ask for confirmation)",
    |clap: App<'static, 'static>| {
        clap.arg(
            Arg::with_name("grace")
                .short("g")
                .long("gracePeriod")
                .help("The duration in seconds before the object should be deleted.")
                .validator(valid_u32)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cascade")
                .short("c")
                .long("cascade")
                .help("Cascading strategy for deletion of any dependent objects.")
                .takes_value(true)
                .possible_values(&["background", "foreground", "orphan"])
                .case_insensitive(true)
                .default_value("background"),
        )
        .arg(
            Arg::with_name("now")
                .long("now")
                .help(
                    "If set, resources are signaled for immediate shutdown \
                     (same as --grace-period=1)",
                )
                .takes_value(false)
                .conflicts_with("grace"),
        )
        .arg(
            Arg::with_name("force")
                .long("force")
                .help(
                    "Force immediate deletion.  For some resources this may result in \
                     inconsistency or data loss",
                )
                .takes_value(false)
                .conflicts_with("grace")
                .conflicts_with("now"),
        )
    },
    vec!["delete"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let grace = if matches.is_present("force") {
            Some(0)
        } else if matches.is_present("now") {
            Some(1)
        } else {
            matches.value_of("grace").map(|grace| {
                grace.parse::<i64>().unwrap() // safe as validated
            })
        };

        let propagation_policy = matches.value_of("cascade").map(|cascade| {
            // k8s requires lowercase with first uppercase
            let lower = cascade.to_lowercase();
            uppercase_first(lower.as_str())
        });

        let delete_options: DeleteOptional = DeleteOptional {
            propagation_policy: propagation_policy.as_deref(),
            grace_period_seconds: grace,
            ..Default::default()
        };

        env.apply_to_selection(
            writer,
            Some(&env.click_config.range_separator),
            |obj, writer| {
                confirm_delete(env, obj, delete_options, writer);
            },
        );
    }
);
