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

use clap::{Arg, Command as ClapCommand};

use rustyline::completion::Pair as RustlinePair;

use crate::{
    command::command_def::{exec_match, start_clap, Cmd},
    completer,
    crd::GetAPIGroupResourcesResponse,
    env::Env,
    error::ClickError,
    k8s_table::{get_k8s_table, GetTableResponse},
    output::ClickWriter,
};

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

struct CrdApiDesc {
    group_version: String,
    name: String,
    namespaced: bool,
}

impl CrdApiDesc {
    fn url(&self, namespace: Option<&str>) -> String {
        if self.namespaced && namespace.is_some() {
            format!(
                "/apis/{}/namespaces/{}/{}",
                self.group_version,
                namespace.as_ref().unwrap(), // safe: checked
                self.name
            )
        } else {
            format!("/apis/{}/{}", self.group_version, self.name)
        }
    }
}

// If the server indicates that it knows about crds named 'name', return the description we can use
// to access them. Otherwise, return None
fn find_desc_for(env: &mut Env, name: &str) -> Result<Option<CrdApiDesc>, ClickError> {
    let groups = crate::crd::get_api_groups(env)?;
    for group in groups.iter() {
        let version = match group.preferred_version.as_ref() {
            Some(pv) => Some(pv.group_version.as_str()),
            None => group.versions.first().map(|v| v.group_version.as_str()),
        };
        if let Some(group_version) = version {
            let (group_req, _) = crate::crd::get_api_group_resources(group_version)?;
            match env.run_on_context::<_, GetAPIGroupResourcesResponse>(|c| c.read(group_req))? {
                GetAPIGroupResourcesResponse::Ok(resp) => {
                    for resource in resp.resources.iter() {
                        if resource.name == name || resource.singular_name == name {
                            return Ok(Some(CrdApiDesc {
                                group_version: group_version.to_string(),
                                name: resource.name.clone(),
                                namespaced: resource.namespaced,
                            }));
                        }
                    }
                }
                GetAPIGroupResourcesResponse::Other(_) => {
                    println!("Error"); // TODO: Print something more useful
                }
            }
        }
    }
    Ok(None)
}

command!(
    Crd,
    "crd",
    "Get a list of resources with the specified name that have been defined by a CRD.",
    |clap: ClapCommand<'static>| clap.arg(
        Arg::new("name")
            .help("The name of the resource defined by a CRD to get")
            .required(true)
            .index(1)
    ),
    vec!["crd"],
    noop_complete!(),
    no_named_complete!(),
    |matches, env, writer| {
        let name = matches.value_of("name").unwrap(); // safe: required
        let api_desc = find_desc_for(env, name)?;
        match api_desc {
            Some(desc) => {
                let (request, _) = get_k8s_table(&desc.url(env.namespace.as_deref()))?;
                match env.run_on_context::<_, GetTableResponse>(|c| c.read(request))? {
                    GetTableResponse::Ok(resp) => {
                        let kobjs = resp.print_to(
                            env,
                            env.namespace.is_none(),
                            &desc.name,
                            &desc.group_version,
                            writer,
                        );
                        env.set_last_objs(kobjs);
                    }
                    GetTableResponse::Other(_) => println!("Other error"),
                }
            }
            None => {
                clickwriteln!(
                    writer,
                    "Cluster doesn't have a CRD created resource of type: {}",
                    name
                );
            }
        }
        Ok(())
    }
);
