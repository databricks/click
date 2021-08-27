use crate::describe;
use crate::kube::Metadata;
use crate::output::ClickWriter;
use crate::values::val_str_opt;
use crate::Env;

use ansi_term::ANSIString;
use ansi_term::Colour::{Blue, Cyan, Green, Purple, Red, Yellow};
use clap::ArgMatches;
use k8s_openapi::api::core::v1 as api;
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
    Namespace,
    PersistentVolume,
}

/// An object we can have as a "current" thing
#[derive(Clone, Debug, PartialEq)]
pub struct KObj {
    pub name: String,
    pub namespace: Option<String>,
    pub typ: ObjType,
}

impl From<crate::kube::PodList> for Vec<KObj> {
    fn from(podlist: crate::kube::PodList) -> Self {
        podlist
            .items
            .iter()
            .map(|pod| {
                let containers = pod
                    .spec
                    .containers
                    .iter()
                    .map(|cspec| cspec.name.clone())
                    .collect();
                KObj::from_metadata(&pod.metadata, ObjType::Pod { containers })
            })
            .collect()
    }
}

impl From<crate::kube::NodeList> for Vec<KObj> {
    fn from(nodelist: crate::kube::NodeList) -> Self {
        nodelist
            .items
            .iter()
            .map(|node| KObj {
                name: node.metadata.name.clone(),
                namespace: None,
                typ: ObjType::Node,
            })
            .collect()
    }
}

impl From<crate::kube::DeploymentList> for Vec<KObj> {
    fn from(deplist: crate::kube::DeploymentList) -> Self {
        deplist
            .items
            .iter()
            .map(|dep| KObj::from_metadata(&dep.metadata, ObjType::Deployment))
            .collect()
    }
}

impl From<crate::kube::ServiceList> for Vec<KObj> {
    fn from(deplist: crate::kube::ServiceList) -> Self {
        deplist
            .items
            .iter()
            .map(|dep| KObj::from_metadata(&dep.metadata, ObjType::Service))
            .collect()
    }
}

pub struct VecWrap {
    items: Vec<KObj>,
}

impl<T: crate::kube::ValueList> From<T> for VecWrap {
    fn from(vlist: T) -> Self {
        let typ = vlist.typ();
        let items = vlist
            .values()
            .iter()
            .map(|val| KObj::from_value(val, typ.clone()).unwrap())
            .collect();
        VecWrap { items }
    }
}

impl From<VecWrap> for Vec<KObj> {
    fn from(vw: VecWrap) -> Self {
        vw.items
    }
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
            ObjType::Namespace => "Namespace",
            ObjType::PersistentVolume => "PersistentVolume",
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
            ObjType::Namespace => Green.bold().paint(self.name.as_str()),
            ObjType::PersistentVolume => Blue.bold().paint(self.name.as_str()),
        }
    }

    pub fn is(&self, typ: ObjType) -> bool {
        self.typ == typ
    }

    // TODO: Move containers elsewhere so this isn't needed
    pub fn is_pod(&self) -> bool {
        matches!(self.typ, ObjType::Pod { .. })
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
            ObjType::Namespace => format!("/apis/v1/namespaces/{}", self.name),
            ObjType::PersistentVolume => format!("/api/v1/persistentvolumes/{}", self.name),
        }
    }

    // do the describe using openapi. when fully migrated this will become just "describe"
    // returns true if the describe was done, false otherwise
    pub fn describe_openapi(
        &self,
        matches: &ArgMatches,
        env: &Env,
        writer: &mut ClickWriter,
    ) -> bool {
        macro_rules! do_describe {
            ($read_func:expr, $resp_typ:ty, $resp_ok:path) => {{
                let (request, _) =
                    $read_func(&self.name, Default::default()).unwrap();
                match env
                    .run_on_context(|c| Ok(c.read::<$resp_typ>(request)))
                    .unwrap()
                    .unwrap() // TODO: Proper error handling
                {
                    $resp_ok(t) => {
                        if !maybe_full_describe_output(matches, &t, writer) {
                            clickwriteln!(writer, "{} {}", self.type_str(), NOTSUPPORTED);
                        }
                    }
                    _ => {}
                }
            }}
        }
        match self.typ {
            ObjType::Namespace => {
                do_describe!(
                    api::Namespace::read_namespace,
                    api::ReadNamespaceResponse,
                    api::ReadNamespaceResponse::Ok
                );
                true
            }
            ObjType::PersistentVolume => {
                do_describe!(
                    api::PersistentVolume::read_persistent_volume,
                    api::ReadPersistentVolumeResponse,
                    api::ReadPersistentVolumeResponse::Ok
                );
                true
            }
            _ => false,
        }
    }

    pub fn describe(&self, matches: &ArgMatches, env: &Env, writer: &mut ClickWriter) {
        if self.describe_openapi(matches, env, writer) {
            return;
        }
        let namespace = match self.typ {
            ObjType::Node => "",
            _ => match self.namespace {
                Some(ref ns) => ns,
                None => {
                    clickwriteln!(writer, "Don't know namespace for {}", self.name());
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
                            clickwriteln!(writer, "{}", describe::describe_format_pod(val))
                        }
                        ObjType::Node => {
                            clickwriteln!(writer, "{}", describe::describe_format_node(val))
                        }
                        ObjType::Deployment => {
                            clickwriteln!(writer, "{}", describe::describe_format_deployment(val))
                        }
                        ObjType::Secret => {
                            clickwriteln!(writer, "{}", describe::describe_format_secret(val))
                        }
                        ObjType::Service => {
                            let url =
                                format!("/api/v1/namespaces/{}/endpoints/{}", namespace, self.name);
                            let endpoint_val = env.run_on_kluster(|k| k.get_value(url.as_str()));
                            clickwriteln!(
                                writer,
                                "{}",
                                describe::describe_format_service(val, endpoint_val)
                            )
                        }
                        _ => clickwriteln!(writer, "{} {}", self.type_str(), NOTSUPPORTED),
                    }
                }
            }
            None => clickwriteln!(writer, "Failed to fetch info from cluster"),
        }
    }
}
