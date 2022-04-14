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

use crate::{env::Env, error::ClickError, output::ClickWriter};
use clap::ArgMatches;
use std::io::Write;

// crd is a bit more complex, so handle it here
pub fn crd_describe(
    name: &str,
    namespace: &str,
    _type: &str,
    group_version: &str,
    matches: &ArgMatches,
    env: &Env,
    writer: &mut ClickWriter,
) -> Result<(), ClickError> {
    //let ns = self.namespace.as_ref().unwrap();
    let (request, _) = crate::crd::read_namespaced_resource(name, namespace, _type, group_version)?;
    match env
        .run_on_context(|c| c.read::<crate::crd::ReadResourceValueResponse>(request))
        .unwrap()
    {
        crate::crd::ReadResourceValueResponse::Ok(t) => {
            if !super::maybe_full_describe_output(matches, &t, writer) {
                clickwriteln!(writer, "{} {}", _type, super::NOTSUPPORTED);
            }
        }
        crate::crd::ReadResourceValueResponse::Other(e) => {
            clickwriteln!(writer, "Error getting response: {:?}", e);
        }
    };
    Ok(())
}
