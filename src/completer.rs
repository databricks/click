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
    env: &'a ::Env,
}

impl<'a> ClickCompleter<'a> {
    /// Create a new ClickCompleter.  We use a raw pointer here because this needs to hold onto a
    /// reference to the env while the main loop is executing, but the main loop also needs to
    /// mutate the env, so the borrow checker complains with safe code.  However, the main loop is
    /// blocked while line-reading (and therefore completion) is ongoing, so using the env read-only
    /// in the complete function below is safe. TODO: File an issue with rustyline to allow a
    /// user-pointer to be passed to readline, which would obviate the need for this
    pub fn new(commands: &'a Vec<Box<Cmd>>, env: *const ::Env) -> ClickCompleter<'a> {
        ClickCompleter {
            commands: commands,
            env: unsafe{&*env},
        }
    }
}

impl<'a> ClickCompleter<'a> {
    fn get_exact_command(&self, line: &str) -> Option<&Box<Cmd>> {
        for cmd in self.commands.iter() {
            if cmd.is(line) {
                return Some(cmd);
            }
        }
        None
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
            let mut split = line.split_whitespace();

            if let Some(linecmd) = split.next() {
                // gather up any none switch type args
                let rest:Vec<&str> = split.filter(|s| {!s.starts_with("-")}).collect();
                if let Some(cmd) = self.get_exact_command(linecmd) {
                    // first thing is a full command, do complete on it
                    let (offset, opts) = cmd.try_complete(rest, self.env);
                    if pos == linecmd.len() && opts.len() > 1 {
                        // user as pressed tab with no space after the command, and we have completions, so add a space in
                        let space_opts = opts.iter().map(|o| {format!(" {}",o)}).collect();
                        return Ok((line.len(), space_opts));
                    } else {
                        return Ok((line.len()-offset, opts));
                    }
                } else {
                    for cmd in self.commands.iter() {
                        if cmd.get_name().starts_with(linecmd) {
                            v.push(cmd.get_name().to_owned());
                        }
                    }
                }
            }
            Ok((0, v))
        }
    }
}
