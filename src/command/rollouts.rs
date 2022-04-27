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

/// Support for argo rollouts https://argoproj.github.io/argo-rollouts/
use clap::{Arg, Command as ClapCommand};
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::ObjectMeta, http, ListOptional, ListResponse,
    ListableResource, Metadata, NamespaceResourceScope, RequestError, Resource, Response,
    ResponseBody, ResponseError,
};
use serde_json::{value::from_value, Error, Value};

use crate::{
    command::command_def::{exec_match, show_arg, sort_arg, start_clap, Cmd},
    command::{get_list_request_for_url, get_read_request_for_url, run_list_command, Extractor},
    completer,
    env::Env,
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
    values::val_num,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

lazy_static! {
    static ref RO_EXTRACTORS: HashMap<String, Extractor<RolloutValue>> = {
        let mut m: HashMap<String, Extractor<RolloutValue>> = HashMap::new();
        m.insert("Current".to_owned(), ro_current);
        m.insert("Desired".to_owned(), ro_desired);
        m.insert("Up To Date".to_owned(), ro_uptodate);
        m.insert("Available".to_owned(), ro_available);
        m
    };
}
const COL_MAP: &[(&str, &str)] = &[
    ("name", "Name"),
    ("desired", "Desired"),
    ("current", "Current"),
    ("uptodate", "Up To Date"),
    ("available", "Available"),
    ("age", "Age"),
];

const COL_FLAGS: &[&str] = &{ extract_first!(COL_MAP) };

const EXTRA_COL_MAP: &[(&str, &str)] = &[("labels", "Labels"), ("namespace", "Namespace")];

const EXTRA_COL_FLAGS: &[&str] = &{ extract_first!(EXTRA_COL_MAP) };

fn ro_to_kobj(rollout: &RolloutValue) -> KObj {
    let meta = &rollout.metadata;
    KObj {
        name: meta.name.clone().unwrap_or_else(|| "<Unknown>".into()),
        namespace: meta.namespace.clone(),
        typ: ObjType::Rollout,
    }
}

fn ro_current(rollout: &RolloutValue) -> Option<CellSpec<'_>> {
    Some(val_num("/status/replicas", &rollout.value, "0").into())
}

fn ro_desired(rollout: &RolloutValue) -> Option<CellSpec<'_>> {
    Some(val_num("/spec/replicas", &rollout.value, "0").into())
}

fn ro_uptodate(rollout: &RolloutValue) -> Option<CellSpec<'_>> {
    Some(val_num("/status/updatedReplicas", &rollout.value, "0").into())
}

fn ro_available(rollout: &RolloutValue) -> Option<CellSpec<'_>> {
    Some(val_num("/status/availableReplicas", &rollout.value, "0").into())
}

list_command!(
    Rollouts,
    "rollouts",
    "Get argo rollouts (in current namespace if set)",
    super::COL_FLAGS,
    super::EXTRA_COL_FLAGS,
    |clap: ClapCommand<'static>| clap
        .arg(
            Arg::new("labels")
                .short('L')
                .long("labels")
                .help("Show statefulsets labels (deprecated, use --show labels)")
                .takes_value(false)
        )
        .arg(
            Arg::new("regex")
                .short('r')
                .long("regex")
                .help("Filter statefulsets by the specified regex")
                .takes_value(true)
        )
        .arg(show_arg(EXTRA_COL_FLAGS, true))
        .arg(sort_arg(COL_FLAGS, Some(EXTRA_COL_FLAGS)))
        .arg(
            Arg::new("reverse")
                .short('R')
                .long("reverse")
                .help("Reverse the order of the returned list")
                .takes_value(false),
        ),
    vec!["rollouts"],
    noop_complete!(),
    [].into_iter(),
    |matches, env, writer| {
        let (request, _response_body) = match &env.namespace {
            Some(ns) => RolloutValue::list_namespaced_rollout(ns, Default::default())?,
            None => RolloutValue::list_rollout_for_all_namespaces(Default::default())?,
        };
        let cols: Vec<&str> = COL_MAP.iter().map(|(_, col)| *col).collect();

        run_list_command(
            matches,
            env,
            writer,
            cols,
            request,
            COL_MAP,
            Some(EXTRA_COL_MAP),
            Some(&RO_EXTRACTORS),
            ro_to_kobj,
        )
    }
);

// Code to deal with sending requests for reading rollouts
/// A rollout value is just a way to implement the various required traits in k8s_openapi to get the
/// serde_json::Value associated with rollouts
#[derive(Debug)]
pub struct RolloutValue {
    pub metadata: ObjectMeta,
    value: Value,
}

impl ListableResource for RolloutValue {
    const LIST_KIND: &'static str = "RolloutList";
}

impl<'de> serde::Deserialize<'de> for RolloutValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let metavalue = value.pointer("/metadata").unwrap();
        let metadata = from_value(metavalue.clone()).unwrap();
        Ok(RolloutValue { value, metadata })
    }
}

impl serde::Serialize for RolloutValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl Metadata for RolloutValue {
    type Ty = ObjectMeta;

    fn metadata(&self) -> &<Self as Metadata>::Ty {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut <Self as Metadata>::Ty {
        &mut self.metadata
    }
}

impl Resource for RolloutValue {
    const API_VERSION: &'static str = "argoproj.io/v1alpha1";
    const GROUP: &'static str = "";
    const KIND: &'static str = "Rollout";
    const VERSION: &'static str = "v1alpha1";
    const URL_PATH_SEGMENT: &'static str = "rollouts";
    type Scope = NamespaceResourceScope;
}

#[derive(Debug)]
pub enum ReadNamespacedRolloutValueResponse {
    Ok(Box<RolloutValue>),
    Other(Result<Option<Value>, Error>),
}

impl Response for ReadNamespacedRolloutValueResponse {
    fn try_from_parts(
        status_code: http::StatusCode,
        buf: &[u8],
    ) -> Result<(Self, usize), ResponseError> {
        match status_code {
            http::StatusCode::OK => {
                let result = match serde_json::from_slice(buf) {
                    Ok(value) => value,
                    Err(err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                    Err(err) => return Err(ResponseError::Json(err)),
                };
                Ok((ReadNamespacedRolloutValueResponse::Ok(result), buf.len()))
            }
            _ => {
                let (result, read) = if buf.is_empty() {
                    (Ok(None), 0)
                } else {
                    match serde_json::from_slice(buf) {
                        Ok(value) => (Ok(Some(value)), buf.len()),
                        Err(err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                        Err(err) => (Err(err), 0),
                    }
                };
                Ok((ReadNamespacedRolloutValueResponse::Other(result), read))
            }
        }
    }
}

impl RolloutValue {
    #[allow(clippy::type_complexity)] // type is from k8s_openapi
    pub fn list_namespaced_rollout(
        namespace: &str,
        optional: ListOptional<'_>,
    ) -> Result<
        (
            http::Request<Vec<u8>>,
            fn(http::StatusCode) -> ResponseBody<ListResponse<Self>>,
        ),
        RequestError,
    > {
        let url = format!(
            "/apis/argoproj.io/v1alpha1/namespaces/{}/rollouts",
            namespace
        );
        get_list_request_for_url(url, optional)
    }

    #[allow(clippy::type_complexity)] // type is from k8s_openapi
    pub fn list_rollout_for_all_namespaces(
        optional: ListOptional<'_>,
    ) -> Result<
        (
            http::Request<Vec<u8>>,
            fn(http::StatusCode) -> ResponseBody<ListResponse<Self>>,
        ),
        RequestError,
    > {
        let url = "/apis/argoproj.io/v1alpha1/rollouts".to_string();
        get_list_request_for_url(url, optional)
    }

    #[allow(clippy::type_complexity)] // type is from k8s_openapi
    pub fn read_namespaced_rollout(
        name: &str,
        namespace: &str,
        _optional: ListOptional<'_>,
    ) -> Result<
        (
            http::Request<Vec<u8>>,
            fn(_: http::StatusCode) -> ResponseBody<ReadNamespacedRolloutValueResponse>,
        ),
        RequestError,
    > {
        let url = format!(
            "/apis/argoproj.io/v1alpha1/namespaces/{}/rollouts/{}",
            namespace, name
        );
        get_read_request_for_url(url)
    }
}
