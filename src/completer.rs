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


use rustyline::completion::Completer;
use rustyline::Result;

use cmd::Cmd;

pub struct ClickCompleter<'a> {
    commands: &'a Vec<Box<Cmd>>,
}

impl<'a> ClickCompleter<'a> {
    pub fn new(commands: &Vec<Box<Cmd>>) -> ClickCompleter {
        ClickCompleter {
            commands: commands,
        }
    }
}

impl<'a> Completer for ClickCompleter<'a> {
    fn complete(&self, line: &str, pos: usize) -> Result<(usize, Vec<String>)> {
        let mut v = Vec::new();
        if pos == 0 {
            for cmd in self.commands.iter() {
                v.push(cmd.get_name().to_owned());
            }
            Ok((0, v))
        } else {
            for cmd in self.commands.iter() {
                if cmd.get_name().starts_with(line) {
                    v.push(cmd.get_name().to_owned());
                }
            }
            Ok((0, v))
        }
    }
}
