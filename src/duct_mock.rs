// Copyright 2017 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test only code to mock out a duct command

use chrono::offset::Utc;

use std::ffi::OsString;
use std::io::Result;

#[derive(Clone)]
pub struct MockExpression {
    cmd: String,
    args: Vec<String>,
}

pub struct MockReader {
    read_from: String,
    pos: usize,
}

impl MockReader {
    fn new(read_from: String) -> MockReader {
        MockReader { read_from, pos: 0 }
    }
}

impl std::io::Read for MockReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let left = self.read_from.len() - self.pos;
        if left == 0 {
            Ok(0)
        } else if left < buf.len() {
            // copy remaining
            buf[0..left].copy_from_slice(&self.read_from.as_bytes()[self.pos..]);
            self.pos += left;
            Ok(left)
        } else {
            // copy what we can
            let lim = self.pos + buf.len();
            buf.copy_from_slice(&self.read_from.as_bytes()[self.pos..lim]);
            self.pos += buf.len();
            Ok(buf.len())
        }
    }
}

impl MockExpression {
    pub fn full_env<T, U, V>(&self, _name_vals: T) -> MockExpression
    where
        T: IntoIterator<Item = (U, V)>,
        U: Into<OsString>,
        V: Into<OsString>,
    {
        self.clone()
    }

    pub fn read(&self) -> Result<String> {
        Ok("".to_string())
    }

    pub fn reader(&self) -> Result<MockReader> {
        match self.cmd.as_str() {
            "aws" => Ok(MockReader::new(format!(
                r#"{{
                  "kind": "ExecCredential",
                  "apiVersion": "client.authentication.k8s.io/v1alpha1",
                  "spec": {{}},
                  "status": {{
                    "expirationTimestamp": "{}",
                    "token": "testtoken"
                  }}
                }}"#,
                (Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ")
            ))),
            _ => Ok(MockReader::new("not found".to_string())),
        }
    }
}

pub fn cmd<T, U>(program: T, args: U) -> MockExpression
where
    T: Into<OsString>,
    U: IntoIterator,
    U::Item: Into<OsString>,
{
    let os: OsString = program.into();
    let args: Vec<String> = args
        .into_iter()
        .map(|a| a.into().into_string().unwrap())
        .collect();
    MockExpression {
        cmd: os.into_string().unwrap(),
        args,
    }
}
