// Copyright 2021 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::describe;
use crate::error::ClickError;
use crate::output::ClickWriter;
use crate::values::val_str_opt;
use crate::Env;

use ansi_term::ANSIString;
use ansi_term::Colour::{Blue, Cyan, Green, Purple, Red, Yellow};
use clap::ArgMatches;
use k8s_openapi::api::{
    apps::v1 as api_apps, batch::v1 as api_batch, core::v1 as api, storage::v1 as api_storage,
};

use serde_json::Value;

use std::io::Write;

#[derive(Clone, Debug, PartialEq)]
pub enum ObjType {
    Pod {
        containers: Vec<String>,
    },
    Crd {
        _type: String,
        group_version: String,
    },
    Node,
    Deployment,
    Service,
    ReplicaSet,
    StatefulSet,
    DaemonSet,
    ConfigMap,
    Secret,
    Job,
    Namespace,
    PersistentVolume,
    StorageClass,
    #[cfg(feature = "argorollouts")]
    Rollout,
}

/// An object we can have as a "current" thing
#[derive(Clone, Debug, PartialEq)]
pub struct KObj {
    pub name: String,
    pub namespace: Option<String>,
    pub typ: ObjType,
}

pub struct VecWrap {
    items: Vec<KObj>,
}

impl From<VecWrap> for Vec<KObj> {
    fn from(vw: VecWrap) -> Self {
        vw.items
    }
}

impl KObj {
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
        match &self.typ {
            ObjType::Pod { .. } => "Pod",
            ObjType::Crd { _type, .. } => _type,
            ObjType::Node => "Node",
            ObjType::DaemonSet => "DaemonSet",
            ObjType::Deployment => "Deployment",
            ObjType::Service => "Service",
            ObjType::ReplicaSet => "ReplicaSet",
            ObjType::StatefulSet => "StatefulSet",
            ObjType::ConfigMap => "ConfigMap",
            ObjType::Secret => "Secret",
            ObjType::Job => "Job",
            ObjType::Namespace => "Namespace",
            ObjType::PersistentVolume => "PersistentVolume",
            ObjType::StorageClass => "StorageClass",
            #[cfg(feature = "argorollouts")]
            ObjType::Rollout => "Rollout",
        }
    }

    pub fn prompt_str(&self) -> ANSIString {
        match self.typ {
            ObjType::Pod { .. } => Yellow.bold().paint(self.name.as_str()),
            ObjType::Crd { .. } => Blue.bold().paint(self.name.as_str()),
            ObjType::Node => Blue.bold().paint(self.name.as_str()),
            ObjType::DaemonSet => Yellow.bold().paint(self.name.as_str()),
            ObjType::Deployment => Purple.bold().paint(self.name.as_str()),
            ObjType::Service => Cyan.bold().paint(self.name.as_str()),
            ObjType::ReplicaSet => Green.bold().paint(self.name.as_str()),
            ObjType::StatefulSet => Green.bold().paint(self.name.as_str()),
            ObjType::ConfigMap => Purple.bold().paint(self.name.as_str()),
            ObjType::Secret => Red.bold().paint(self.name.as_str()),
            ObjType::Job => Purple.bold().paint(self.name.as_str()),
            ObjType::Namespace => Green.bold().paint(self.name.as_str()),
            ObjType::PersistentVolume => Blue.bold().paint(self.name.as_str()),
            ObjType::StorageClass => Red.bold().paint(self.name.as_str()),
            #[cfg(feature = "argorollouts")]
            ObjType::Rollout => Purple.bold().paint(self.name.as_str()),
        }
    }

    pub fn is(&self, typ: ObjType) -> bool {
        self.typ == typ
    }

    // TODO: Move containers elsewhere so this isn't needed
    pub fn is_pod(&self) -> bool {
        matches!(self.typ, ObjType::Pod { .. })
    }

    /// describe the object represented by this kobj
    pub fn describe(
        &self,
        matches: &ArgMatches,
        env: &Env,
        writer: &mut ClickWriter,
    ) -> Result<(), ClickError> {
        // we use some macro hacking here as each read_x call returns different types that have no
        // common trait we could rely on to write generic code
        macro_rules! do_describe {
            ($read_func:expr, $resp_typ:ty, $resp_ok:path, $custom_desc: expr) => {{
                let (request, _) = $read_func(&self.name, Default::default())?;
                match env
                    .run_on_context(|c| c.read::<$resp_typ>(request))
                    .unwrap()
                {
                    $resp_ok(t) => {
                        if !describe::maybe_full_describe_output(matches, &t, writer) {
                            let desc_func: Option<fn(Value) -> String> = $custom_desc;
                            match desc_func {
                                Some(custom) => {
                                    let val = serde_json::value::to_value(&t).unwrap();
                                    clickwriteln!(writer, "{}", custom(val));
                                }
                                None => {
                                    clickwriteln!(
                                        writer,
                                        "{} {}",
                                        self.type_str(),
                                        describe::NOTSUPPORTED
                                    );
                                }
                            }
                        }
                    }
                    _ => {} // TODO
                }
            }};
        }
        macro_rules! do_describe_with_namespace {
            // TODO: It would be nice to merge these two
            ($read_func: expr, $resp_typ: ty, $resp_ok: path) => {
                match self.namespace.as_ref() {
                    Some(ns) => {
                        let (request, _) = $read_func(&self.name, ns, Default::default())?;
                        match env
                            .run_on_context(|c| c.read::<$resp_typ>(request))
                            .unwrap()
                        {
                            $resp_ok(t) => {
                                if !describe::maybe_full_describe_output(matches, &t, writer) {
                                    describe::describe_metadata(&t, writer)?;
                                }
                            }
                            _ => {}
                        }
                    }
                    None => {
                        clickwriteln!(writer, "No namespace for {}, cannot describe", self.name);
                    }
                }
            };
            ($read_func: expr, $resp_typ: ty, $resp_ok: path, $custom_desc: expr) => {
                match self.namespace.as_ref() {
                    Some(ns) => {
                        let (request, _) = $read_func(&self.name, ns, Default::default())?;
                        match env
                            .run_on_context(|c| c.read::<$resp_typ>(request))
                            .unwrap()
                        {
                            $resp_ok(t) => {
                                if !describe::maybe_full_describe_output(matches, &t, writer) {
                                    let val = serde_json::value::to_value(&t).unwrap();
                                    clickwriteln!(writer, "{}", $custom_desc(val));
                                }
                            }
                            _ => {}
                        }
                    }
                    None => {
                        clickwriteln!(writer, "No namespace for {}, cannot describe", self.name);
                    }
                }
            };
        }
        match self.typ {
            ObjType::ConfigMap => {
                do_describe_with_namespace!(
                    api::ConfigMap::read_namespaced_config_map,
                    api::ReadNamespacedConfigMapResponse,
                    api::ReadNamespacedConfigMapResponse::Ok
                );
            }
            ObjType::DaemonSet => {
                do_describe_with_namespace!(
                    api_apps::DaemonSet::read_namespaced_daemon_set,
                    api_apps::ReadNamespacedDaemonSetResponse,
                    api_apps::ReadNamespacedDaemonSetResponse::Ok
                );
            }
            ObjType::Deployment => {
                do_describe_with_namespace!(
                    api_apps::Deployment::read_namespaced_deployment,
                    api_apps::ReadNamespacedDeploymentResponse,
                    api_apps::ReadNamespacedDeploymentResponse::Ok,
                    describe::legacy::describe_format_deployment
                );
            }
            ObjType::Job => {
                do_describe_with_namespace!(
                    api_batch::Job::read_namespaced_job,
                    api_batch::ReadNamespacedJobResponse,
                    api_batch::ReadNamespacedJobResponse::Ok
                );
            }
            ObjType::Namespace => {
                do_describe!(
                    api::Namespace::read_namespace,
                    api::ReadNamespaceResponse,
                    api::ReadNamespaceResponse::Ok,
                    None
                );
            }
            ObjType::Node => {
                do_describe!(
                    api::Node::read_node,
                    api::ReadNodeResponse,
                    api::ReadNodeResponse::Ok,
                    Some(describe::legacy::describe_format_node)
                );
            }
            ObjType::PersistentVolume => {
                do_describe!(
                    api::PersistentVolume::read_persistent_volume,
                    api::ReadPersistentVolumeResponse,
                    api::ReadPersistentVolumeResponse::Ok,
                    None
                );
            }
            ObjType::Pod { .. } => {
                do_describe_with_namespace!(
                    api::Pod::read_namespaced_pod,
                    api::ReadNamespacedPodResponse,
                    api::ReadNamespacedPodResponse::Ok,
                    describe::legacy::describe_format_pod
                );
            }
            ObjType::ReplicaSet => {
                do_describe_with_namespace!(
                    api_apps::ReplicaSet::read_namespaced_replica_set,
                    api_apps::ReadNamespacedReplicaSetResponse,
                    api_apps::ReadNamespacedReplicaSetResponse::Ok
                );
            }
            ObjType::Secret => {
                do_describe_with_namespace!(
                    api::Secret::read_namespaced_secret,
                    api::ReadNamespacedSecretResponse,
                    api::ReadNamespacedSecretResponse::Ok,
                    describe::legacy::describe_format_secret
                );
            }
            ObjType::Service => {
                describe::service::service_describe(
                    &self.name,
                    self.namespace.as_ref().unwrap(),
                    matches,
                    env,
                    writer,
                )?;
            }
            ObjType::StatefulSet => {
                do_describe_with_namespace!(
                    api_apps::StatefulSet::read_namespaced_stateful_set,
                    api_apps::ReadNamespacedStatefulSetResponse,
                    api_apps::ReadNamespacedStatefulSetResponse::Ok
                );
            }
            ObjType::StorageClass => {
                do_describe!(
                    api_storage::StorageClass::read_storage_class,
                    api_storage::ReadStorageClassResponse,
                    api_storage::ReadStorageClassResponse::Ok,
                    None
                );
            }
            ObjType::Crd {
                ref _type,
                ref group_version,
            } => {
                describe::crd::crd_describe(
                    &self.name,
                    self.namespace.as_ref().unwrap(),
                    _type,
                    group_version,
                    matches,
                    env,
                    writer,
                )?;
            }
            #[cfg(feature = "argorollouts")]
            ObjType::Rollout => {
                use crate::command::rollouts;
                do_describe_with_namespace!(
                    rollouts::RolloutValue::read_namespaced_rollout,
                    rollouts::ReadNamespacedRolloutValueResponse,
                    rollouts::ReadNamespacedRolloutValueResponse::Ok,
                    describe::legacy::describe_format_rollout
                );
            }
        }
        Ok(())
    }
}
