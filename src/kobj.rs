use describe;
use kube::Metadata;
use output::ClickWriter;
use values::val_str_opt;
use Env;

use ansi_term::ANSIString;
use ansi_term::Colour::{Blue, Cyan, Green, Purple, Red, Yellow};
use clap::ArgMatches;
use serde::ser::Serialize;
use serde_json::Value;

use std::io::Write;

#[derive(Clone, Debug, PartialEq)]
pub enum ObjType {
    Pod { containers: Vec<String> },
    Node,
    Deployment,
    Service,
    ReplicaSet,
    StatefulSet,
    ConfigMap,
    Secret,
    Job,
}

/// An object we can have as a "current" thing
#[derive(Clone, Debug, PartialEq)]
pub struct KObj {
    pub name: String,
    pub namespace: Option<String>,
    pub typ: ObjType,
}

fn maybe_full_describe_output<T: ?Sized>(
    matches: &ArgMatches,
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
    pub fn from_metadata(metadata: &Metadata, typ: ObjType) -> KObj {
        KObj {
            name: metadata.name.clone(),
            namespace: metadata.namespace.clone(),
            typ,
        }
    }

    pub fn from_value(value: &Value, typ: ObjType) -> Option<KObj> {
        val_str_opt("/metadata/name", value).map(|name| KObj {
            name,
            namespace: val_str_opt("/metadata/namespace", value),
            typ,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn type_str(&self) -> &str {
        match self.typ {
            ObjType::Pod { .. } => "Pod",
            ObjType::Node => "Node",
            ObjType::Deployment => "Deployment",
            ObjType::Service => "Service",
            ObjType::ReplicaSet => "ReplicaSet",
            ObjType::StatefulSet => "StatefulSet",
            ObjType::ConfigMap => "ConfigMap",
            ObjType::Secret => "Secret",
            ObjType::Job => "Job",
        }
    }

    pub fn prompt_str(&self) -> ANSIString {
        match self.typ {
            ObjType::Pod { .. } => Yellow.bold().paint(self.name.as_str()),
            ObjType::Node => Blue.bold().paint(self.name.as_str()),
            ObjType::Deployment => Purple.bold().paint(self.name.as_str()),
            ObjType::Service => Cyan.bold().paint(self.name.as_str()),
            ObjType::ReplicaSet => Green.bold().paint(self.name.as_str()),
            ObjType::StatefulSet => Green.bold().paint(self.name.as_str()),
            ObjType::ConfigMap => Purple.bold().paint(self.name.as_str()),
            ObjType::Secret => Red.bold().paint(self.name.as_str()),
            ObjType::Job => Purple.bold().paint(self.name.as_str()),
        }
    }

    pub fn is(&self, typ: ObjType) -> bool {
        self.typ == typ
    }

    // TODO: Move containers elsewhere so this isn't needed
    pub fn is_pod(&self) -> bool {
        if let ObjType::Pod { .. } = self.typ {
            true
        } else {
            false
        }
    }

    pub fn url(&self, namespace: &str) -> String {
        match self.typ {
            ObjType::Pod { .. } => format!("/api/v1/namespaces/{}/pods/{}", namespace, self.name),
            ObjType::Node => format!("/api/v1/nodes/{}", self.name),
            ObjType::Deployment => format!(
                "/apis/extensions/v1beta1/namespaces/{}/deployments/{}",
                namespace, self.name
            ),
            ObjType::Service => format!("/api/v1/namespaces/{}/services/{}", namespace, self.name),
            ObjType::ReplicaSet => format!(
                "/apis/extensions/v1beta1/namespaces/{}/replicasets/{}",
                namespace, self.name
            ),
            ObjType::StatefulSet => format!(
                "/apis/apps/v1beta1/namespaces/{}/statefulsets/{}",
                namespace, self.name
            ),
            ObjType::ConfigMap => {
                format!("/api/v1/namespaces/{}/configmaps/{}", namespace, self.name)
            }
            ObjType::Secret => format!("/api/v1/namespaces/{}/secrets/{}", namespace, self.name),
            ObjType::Job => format!("/apis/batch/v1/namespaces/{}/jobs/{}", namespace, self.name),
        }
    }

    pub fn describe(&self, matches: &ArgMatches, env: &Env, writer: &mut ClickWriter) {
        let namespace = match self.typ {
            ObjType::Node => "",
            _ => match self.namespace {
                Some(ref ns) => ns,
                None => {
                    clickwrite!(writer, "Don't know namespace for {}\n", self.name());
                    return;
                }
            },
        };

        let url = self.url(namespace);
        match env.run_on_kluster(|k| k.get_value(url.as_str())) {
            Some(val) => {
                if !maybe_full_describe_output(matches, &val, writer) {
                    match self.typ {
                        ObjType::Pod { .. } => {
                            clickwrite!(writer, "{}\n", describe::describe_format_pod(val))
                        }
                        ObjType::Node => {
                            clickwrite!(writer, "{}\n", describe::describe_format_node(val))
                        }
                        ObjType::Secret => {
                            clickwrite!(writer, "{}\n", describe::describe_format_secret(val))
                        }
                        ObjType::Service => {
                            let url =
                                format!("/api/v1/namespaces/{}/endpoints/{}", namespace, self.name);
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
