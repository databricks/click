use describe;
use output::ClickWriter;
use Env;

use clap::ArgMatches;
use serde::ser::Serialize;

use std::io::Write;

/// An object we can have as a "current" thing
// TODO(nick): This should hold the namespace too
pub enum KObj {
    Pod {
        name: String,
        containers: Vec<String>,
    },
    Node(String),
    Deployment(String),
    Service(String),
    ReplicaSet(String),
    StatefulSet(String),
    ConfigMap(String),
    Secret(String),
    Job(String),
}

fn maybe_full_describe_output<T: ?Sized>(
    matches: ArgMatches,
    value: &T,
    writer: &mut ClickWriter,
) -> bool
where
    T: Serialize,
{
    if matches.is_present("json") {
        writer.pretty_color_json(value).unwrap_or(());
        true
    } else if matches.is_present("yaml") {
        writer.print_yaml(value).unwrap_or(());
        true
    } else {
        false
    }
}

static NOTSUPPORTED: &str = "not supported without -j or -y yet\n";

impl KObj {
    pub fn name(&self) -> &str {
        match self {
            KObj::Pod { name, .. } => name,
            KObj::Node(name)
            | KObj::Deployment(name)
            | KObj::Service(name)
            | KObj::ReplicaSet(name)
            | KObj::StatefulSet(name)
            | KObj::ConfigMap(name)
            | KObj::Secret(name)
            | KObj::Job(name) => name,
        }
    }

    pub fn type_str(&self) -> &str {
        match self {
            KObj::Pod { .. } => "Pod",
            KObj::Node(_) => "Node",
            KObj::Deployment(_) => "Deployment",
            KObj::Service(_) => "Service",
            KObj::ReplicaSet(_) => "ReplicaSet",
            KObj::StatefulSet(_) => "StatefulSet",
            KObj::ConfigMap(_) => "ConfigMap",
            KObj::Secret(_) => "Secret",
            KObj::Job(_) => "Job",
        }
    }

    pub fn info_url(&self, namespace: &str) -> String {
        match self {
            KObj::Pod { name, .. } => format!("/api/v1/namespaces/{}/pods/{}", namespace, name),
            KObj::Node(name) => format!("/api/v1/nodes/{}", name),
            KObj::Deployment(name) => format!(
                "/apis/extensions/v1beta1/namespaces/{}/deployments/{}",
                namespace, name
            ),
            KObj::Service(name) => format!("/api/v1/namespaces/{}/services/{}", namespace, name),
            KObj::ReplicaSet(name) => format!(
                "/apis/extensions/v1beta1/namespaces/{}/replicasets/{}",
                namespace, name
            ),
            KObj::StatefulSet(name) => format!(
                "/apis/apps/v1beta1/namespaces/{}/statefulsets/{}",
                namespace, name
            ),
            KObj::ConfigMap(name) => {
                format!("/api/v1/namespaces/{}/configmaps/{}", namespace, name)
            }
            KObj::Secret(name) => format!("/api/v1/namespaces/{}/secrets/{}", namespace, name),
            KObj::Job(name) => format!("/apis/batch/v1/namespaces/{}/jobs/{}", namespace, name),
        }
    }

    pub fn describe(&self, matches: ArgMatches, env: &Env, writer: &mut ClickWriter) {
        let namespace = if env.current_object_namespace.is_none() {
            match self {
                KObj::Node(_) => "", // not used
                _ => {
                    clickwrite!(writer, "Don't know namespace for {}\n", self.name());
                    return;
                }
            }
        } else {
            env.current_object_namespace.as_ref().unwrap()
        };
        let url = self.info_url(namespace);
        match env.run_on_kluster(|k| k.get_value(url.as_str())) {
            Some(val) => {
                if !maybe_full_describe_output(matches, &val, writer) {
                    match self {
                        KObj::Pod { .. } => {
                            clickwrite!(writer, "{}\n", describe::describe_format_pod(val))
                        }
                        KObj::Node(_) => {
                            clickwrite!(writer, "{}\n", describe::describe_format_node(val))
                        }
                        KObj::Secret(_) => {
                            clickwrite!(writer, "{}\n", describe::describe_format_secret(val))
                        }
                        KObj::Service(service) => {
                            let url =
                                format!("/api/v1/namespaces/{}/endpoints/{}", namespace, service);
                            let endpoint_val = env.run_on_kluster(|k| k.get_value(url.as_str()));
                            clickwrite!(
                                writer,
                                "{}\n",
                                describe::describe_format_service(val, endpoint_val)
                            )
                        }
                        _ => clickwrite!(writer, "{} {}", self.type_str(), NOTSUPPORTED),
                    }
                }
            }
            None => clickwrite!(writer, "Failed to fetch info from cluster"),
        }
    }
}
