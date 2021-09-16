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

use crate::cmd::Cmd;
//use config::Alias;
use crate::env::Env;
use crate::kobj::ObjType;

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::{Context, Helper, Result};

use std::rc::Rc;

pub struct ClickHelper {
    commands: Vec<Box<dyn Cmd>>,
    help_topics: Vec<&'static str>,
    env: Option<Rc<Env>>,
    command_completions: Vec<String>,
}

impl Helper for ClickHelper {}

impl Highlighter for ClickHelper {}

impl Hinter for ClickHelper {
    fn hint(&self, _line: &str, _pos: usize, _context: &Context) -> Option<String> {
        None
    }
}

// get a vec with strings that could complete commands or aliases
fn get_command_completion_strings(commands: &[Box<dyn Cmd>], env: Option<&Rc<Env>>) -> Vec<String> {
    let mut v = vec!["help".to_string()];
    for cmd in commands.iter() {
        v.push(cmd.get_name().to_string());
    }
    if let Some(env) = env.as_ref() {
        for alias in env.click_config.aliases.iter() {
            v.push(alias.alias.to_string());
        }
    }
    v.sort_unstable();
    v
}

impl ClickHelper {
    /// Create a new completer. help_topics are any extra things you can type after 'help' that
    /// aren't commands
    pub fn new(commands: Vec<Box<dyn Cmd>>, help_topics: Vec<&'static str>) -> ClickHelper {
        let command_completions = get_command_completion_strings(&commands, None);
        ClickHelper {
            commands,
            help_topics,
            env: None,
            command_completions,
        }
    }

    pub fn set_env(&mut self, env: Option<Rc<Env>>) {
        self.env = env;
        let command_completions = get_command_completion_strings(&self.commands, self.env.as_ref());
        self.command_completions = command_completions;
    }

    #[allow(clippy::borrowed_box)]
    fn get_exact_command(&self, line: &str) -> Option<&Box<dyn Cmd>> {
        for cmd in self.commands.iter() {
            if cmd.is(line) {
                return Some(cmd);
            }
        }
        None
    }

    /// complete a line that starts with a full command. This should only be called when we know
    /// that the string contains a space. cmd_len is the length of the string the user has typed,
    /// which can be different than `line.len()` due to alias expansion.
    fn complete_exact_command(&self, line: &str, cmd_len: usize) -> (usize, Vec<Pair>) {
        let mut split = line.split_whitespace();
        let linecmd = split.next().unwrap(); // safe, only ever call this if we know there's a space
                                             // gather up any none switch type args
        if let Some(cmd) = self.get_exact_command(linecmd) {
            // first thing is a full command, do complete on it
            // check what we're trying to complete
            let (pos, prefix, last_opt) = match split.next_back() {
                Some(back) => {
                    // there was a command typed and also something after it
                    if line.ends_with(' ') {
                        // ending with a space means complete a positional or a opt arg
                        let mut count = split.filter(|s| !s.starts_with('-')).count();
                        let last_opt = if back.starts_with('-') {
                            Some(back)
                        } else {
                            // if the last thing didn't have a -, it's a positional arg that we need
                            // to count
                            count += 1;
                            None
                        };
                        (count, "", last_opt)
                    } else if back == "-" {
                        // a lone - completes with another -
                        return (
                            cmd_len,
                            vec![Pair {
                                display: "-".to_owned(),
                                replacement: "-".to_owned(),
                            }],
                        );
                    } else if let Some(opt_str) = back.strip_prefix("--") {
                        // last thing is a long option, complete on available options
                        let mut opts = cmd.complete_option(opt_str);
                        if "--help".starts_with(back) {
                            // add in help completion
                            opts.push(Pair {
                                display: "--help".to_owned(),
                                replacement: "help"[(back.len() - 2)..].to_owned(),
                            });
                        }
                        return (cmd_len, opts);
                    } else {
                        // last thing isn't an option, figure out which positional we're at
                        let mut prev_arg = split.next_back();
                        let mut count = split.filter(|s| !s.starts_with('-')).count();
                        if let Some(pa) = prev_arg {
                            if !pa.starts_with('-') {
                                // need to count prev_arg as positional as it doesn't start with -
                                // also make prev_arg None as it's not a -- arg
                                count += 1;
                                prev_arg = None;
                            }
                        }
                        (count, back, prev_arg)
                    }
                }
                None => (0, "", None),
            };
            // here the last thing typed wasn't a '-' option, so we ask the command to
            // do completion
            if let Some(ref env) = self.env {
                match last_opt {
                    Some(opt) => {
                        let opts = cmd.try_completed_named(pos, opt, prefix, &*env);
                        (cmd_len, opts)
                    }
                    None => {
                        let opts = cmd.try_complete(pos, prefix, &*env);
                        (cmd_len, opts)
                    }
                }
            } else {
                (0, vec![])
            }
        } else if linecmd == "help" {
            let cmd_part = split.next().unwrap_or("");
            if split.next().is_none() {
                let mut v = vec![];
                // only complete on the first arg to help
                self.get_command_completions(cmd_part, &mut v);
                self.get_help_completions(cmd_part, &mut v);
                (5, v) // help plus space is 5 chars
            } else {
                (0, vec![])
            }
        } else {
            (0, vec![])
        }
    }

    /// Find all commands or aliases that start with `line`
    fn get_command_completions(&self, line: &str, candidates: &mut Vec<Pair>) {
        for opt in self.command_completions.iter() {
            if opt.starts_with(line) {
                candidates.push(Pair {
                    display: opt.clone(),
                    replacement: format!("{} ", opt),
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

    // fn get_aliases(&self) -> Option<&Vec<Alias>> {
    //     self.env.as_ref().map(|e| &e.click_config.aliases)
    // }

    fn completion_vec(&self) -> Vec<Pair> {
        self.command_completions
            .iter()
            .map(|s| Pair {
                display: s.clone(),
                replacement: format!("{} ", s),
            })
            .collect()
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
        if pos == 0 {
            Ok((0, self.completion_vec()))
        } else if line.contains(char::is_whitespace) {
            // we do have a space, so now see if the first thing typed is a command, and
            // complete on it

            // if possible, turn an alias into a real command
            let expanded = self
                .env
                .as_ref()
                .map(|e| crate::command_processor::alias_expand_line(e, line));
            Ok(self.complete_exact_command(expanded.as_deref().unwrap_or(line), line.len()))
        } else {
            // no command with space, so just complete commands
            let mut v = Vec::new();
            self.get_command_completions(line, &mut v);
            Ok((0, v))
        }
    }
}

// Individual completers are below
pub fn context_complete(prefix: &str, env: &Env) -> Vec<Pair> {
    let mut v = Vec::new();
    for context in env.config.contexts.keys() {
        if let Some(rest) = context.strip_prefix(prefix) {
            v.push(Pair {
                display: context.to_string(),
                replacement: rest.to_string(),
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
    if let Some(pod) = env.current_pod() {
        if let ObjType::Pod { ref containers } = pod.typ {
            for cont in containers.iter() {
                if let Some(rest) = cont.strip_prefix(prefix) {
                    v.push(Pair {
                        display: cont.clone(),
                        replacement: rest.to_string(),
                    });
                }
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
                if let Some(rest) = val.strip_prefix(prefix) {
                    v.push(Pair {
                        display: val.to_string(),
                        replacement: rest.to_string(),
                    });
                }
            }
            v
        }
    };
}

possible_values_completer!(setoptions_values_completer, crate::command::click::SET_OPTS);

possible_values_completer!(
    portforwardaction_values_completer,
    ["list", "output", "stop"]
);

possible_values_completer!(
    deployment_sort_values_completer,
    [
        "Name",
        "name",
        "Desired",
        "desired",
        "Current",
        "current",
        "UpToDate",
        "uptodate",
        "Available",
        "available",
        "Age",
        "age",
        "Labels",
        "labels"
    ]
);

possible_values_completer!(
    service_sort_values_completer,
    [
        "Name",
        "name",
        "ClusterIP",
        "clusterip",
        "ExternalIP",
        "externalip",
        "Age",
        "age",
        "Ports",
        "ports",
        "Labels",
        "labels",
        "Namespace",
        "namespace"
    ]
);
