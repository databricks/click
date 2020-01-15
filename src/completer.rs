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

use cmd::Cmd;
use env::{Env, KObj};

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::{Context, Helper, Result};

use std::rc::Rc;

pub struct ClickHelper {
    commands: Vec<Box<dyn Cmd>>,
    help_topics: Vec<&'static str>,
    env: Option<Rc<Env>>,
}

impl Helper for ClickHelper {}

impl Highlighter for ClickHelper {}

impl Hinter for ClickHelper {
    fn hint(&self, _line: &str, _pos: usize, _context: &Context) -> Option<String> {
        None
    }
}

impl ClickHelper {
    /// Create a new completer. help_topics are any extra things you can type after 'help' that
    /// aren't commands
    pub fn new(commands: Vec<Box<dyn Cmd>>, help_topics: Vec<&'static str>) -> ClickHelper {
        ClickHelper {
            commands,
            help_topics,
            env: None,
        }
    }

    pub fn set_env(&mut self, env: Option<Rc<Env>>) {
        self.env = env;
    }
}

impl ClickHelper {
    #[allow(clippy::borrowed_box)]
    fn get_exact_command(&self, line: &str) -> Option<&Box<dyn Cmd>> {
        for cmd in self.commands.iter() {
            if cmd.is(line) {
                return Some(cmd);
            }
        }
        None
    }

    fn get_command_completions(&self, line: &str, candidates: &mut Vec<Pair>) {
        for cmd in self.commands.iter() {
            if cmd.get_name().starts_with(line) {
                candidates.push(Pair {
                    display: cmd.get_name().to_owned(),
                    replacement: cmd.get_name().to_owned(),
                });
            }
        }
    }

    fn get_help_completions(&self, line: &str, candidates: &mut Vec<Pair>) {
        for topic in self.help_topics.iter() {
            if topic.starts_with(line) {
                candidates.push(Pair {
                    display: (*topic).to_string(),
                    replacement: (*topic).to_string(),
                });
            }
        }
    }
}

/// Does the short option (an Option<char>) from clap match
pub fn long_matches(long: &Option<&str>, prefix: &str) -> bool {
    match long {
        Some(lstr) => lstr.starts_with(prefix),
        None => false,
    }
}

impl Completer for ClickHelper {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context) -> Result<(usize, Vec<Pair>)> {
        let mut v = Vec::new();
        if pos == 0 {
            for cmd in self.commands.iter() {
                v.push(Pair {
                    display: cmd.get_name().to_owned(),
                    replacement: cmd.get_name().to_owned(),
                });
            }
            Ok((0, v))
        } else {
            let mut split = line.split_whitespace();
            if let Some(linecmd) = split.next() {
                // gather up any none switch type args
                //let rest: Vec<&str> = split.filter(|s| !s.starts_with("-")).collect();
                if let Some(cmd) = self.get_exact_command(linecmd) {
                    // first thing is a full command, do complete on it

                    // check what we're trying to complete
                    let (pos, prefix) = match split.next_back() {
                        Some(back) => {
                            // there was a command typed and also something after it
                            if line.ends_with(' ') {
                                // ending with a space means complete a positional
                                let mut count = split.filter(|s| !s.starts_with('-')).count();
                                if !back.starts_with('-') {
                                    // if the last thing didn't have a -, it's a positional arg
                                    // that we need to count
                                    count += 1;
                                }
                                (count, "")
                            } else if back == "-" {
                                // a lone - completes with another -
                                return Ok((
                                    line.len(),
                                    vec![Pair {
                                        display: "-".to_owned(),
                                        replacement: "-".to_owned(),
                                    }],
                                ));
                            } else if back.starts_with("--") {
                                // last thing is a long option, complete on available options
                                let mut opts = cmd.complete_option(&back[2..]);
                                if "--help".starts_with(back) {
                                    // add in help completion
                                    opts.push(Pair {
                                        display: "--help".to_owned(),
                                        replacement: "help"[(back.len() - 2)..].to_owned(),
                                    });
                                }
                                return Ok((line.len(), opts));
                            } else {
                                // last thing isn't an option, figure out which positional we're at
                                (split.filter(|s| !s.starts_with('-')).count(), back)
                            }
                        }
                        None => (0, ""),
                    };
                    // here the last thing typed wasn't a '-' option, so we ask the command to
                    // do completion
                    if let Some(ref env) = self.env {
                        let opts = cmd.try_complete(pos, prefix, &*env);
                        return Ok((line.len(), opts));
                    } else {
                        return Ok((0, v));
                    }
                } else if linecmd == "help" {
                    let cmd_part = split.next().unwrap_or("");
                    if split.next().is_none() {
                        // only complete on the first arg to help
                        self.get_command_completions(cmd_part, &mut v);
                        self.get_help_completions(cmd_part, &mut v);
                        return Ok((5, v)); // help plus space is 5 chars
                    }
                } else {
                    self.get_command_completions(linecmd, &mut v);
                    if "help".starts_with(linecmd) {
                        v.push(Pair {
                            display: "help".to_string(),
                            replacement: "help".to_string(),
                        });
                    }
                }
            }
            Ok((0, v))
        }
    }
}

// Individual completers are below
pub fn context_complete(prefix: &str, env: &Env) -> Vec<Pair> {
    let mut v = Vec::new();
    for context in env.config.contexts.keys() {
        if context.starts_with(prefix) {
            v.push(Pair {
                display: context.to_string(),
                replacement: context[prefix.len()..].to_string(),
            })
        }
    }
    v
}

pub fn namespace_completer(prefix: &str, env: &Env) -> Vec<Pair> {
    match env.run_on_kluster(|k| k.namespaces_for_context()) {
        Some(v) => v
            .iter()
            .filter(|ns| ns.starts_with(prefix))
            .map(|ns| Pair {
                display: ns.clone(),
                replacement: ns[prefix.len()..].to_string(),
            })
            .collect(),
        None => vec![],
    }
}

pub fn container_completer(prefix: &str, env: &Env) -> Vec<Pair> {
    let mut v = vec![];
    if let KObj::Pod { ref containers, .. } = env.current_object {
        for cont in containers.iter() {
            if cont.starts_with(prefix) {
                v.push(Pair {
                    display: cont.clone(),
                    replacement: cont[prefix.len()..].to_string(),
                });
            }
        }
    }
    v
}

macro_rules! possible_values_completer {
    ($name: ident, $values: expr) => {
        pub fn $name(prefix: &str, _env: &Env) -> Vec<Pair> {
            let mut v = vec![];
            for val in $values.iter() {
                if val.starts_with(prefix) {
                    v.push(Pair {
                        display: val.to_string(),
                        replacement: val[prefix.len()..].to_string(),
                    });
                }
            }
            v
        }
    };
}

possible_values_completer!(
    setoptions_values_completer,
    ["completion_type", "edit_mode", "editor", "terminal"]
);
possible_values_completer!(
    portforwardaction_values_completer,
    ["list", "output", "stop"]
);
