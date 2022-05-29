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

use crate::config::{self, Alias, ClickConfig, Config};
use crate::error::ClickError;
use crate::kobj::{KObj, ObjType};
use crate::output::ClickWriter;
use crate::styles::Styles;

use rustyline::config as rustyconfig;
use strfmt::strfmt;
use tempdir::TempDir;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// TODO: Maybe make less of this pub

/// An ongoing port forward
pub struct PortForward {
    pub child: Child,
    pub pod: String,
    pub ports: Vec<String>,
    pub output: Arc<Mutex<String>>,
}

#[derive(Debug)]
pub struct ExpandedAlias<'a> {
    pub expansion: Option<&'a Alias>,
    pub rest: &'a str,
}

#[derive(Debug, PartialEq)]
pub enum ObjectSelection {
    Single(KObj),
    Range(Vec<KObj>),
    None,
}

/// Keep track of our repl environment
pub struct Env {
    pub config: Config,
    pub click_config: ClickConfig,
    pub styles: Styles,
    click_config_path: PathBuf,
    pub quit: bool,
    pub need_new_editor: bool,
    pub context: Option<super::k8s::Context>,
    pub namespace: Option<String>,
    current_selection: ObjectSelection,
    last_objs: Option<Vec<KObj>>,
    pub ctrlcbool: Arc<AtomicBool>,
    port_forwards: Vec<PortForward>,
    pub prompt: String,
    range_str: Option<String>,
    pub tempdir: std::io::Result<TempDir>,
}

lazy_static! {
    static ref CTC_BOOL: Arc<AtomicBool> = {
        let b = Arc::new(AtomicBool::new(false));
        let r = b.clone();
        ctrlc::set_handler(move || {
            r.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
        b
    };
}

impl Env {
    pub fn new(config: Config, click_config: ClickConfig, click_config_path: PathBuf) -> Env {
        let namespace = click_config.namespace.clone();
        let context = click_config.context.clone();
        let styles = Styles::new();
        let nones = (
            styles.prompt_context("none"),
            styles.prompt_namespace("none"),
            styles.prompt_select_none("none"),
        );
        let mut env = Env {
            config,
            click_config,
            styles,
            click_config_path,
            quit: false,
            need_new_editor: false,
            context: None,
            namespace,
            current_selection: ObjectSelection::None,
            last_objs: None,
            ctrlcbool: CTC_BOOL.clone(),
            port_forwards: Vec::new(),
            prompt: format!("[{}] [{}] [{}] > ", nones.0, nones.1, nones.2,),
            range_str: None,
            tempdir: TempDir::new("click"),
        };
        env.set_context(context.as_deref());
        env
    }

    pub fn current_selection(&self) -> &ObjectSelection {
        &self.current_selection
    }

    pub fn save_click_config(&mut self) {
        self.click_config.namespace = self.namespace.clone();
        self.click_config.context = self.context.as_ref().map(|c| c.name.clone());
        self.click_config
            .save_to_file(self.click_config_path.as_path().to_str().unwrap())
            .unwrap();
    }

    // sets the prompt string based on current settings
    fn set_prompt(&mut self) {
        self.prompt = format!(
            "[{}] [{}] [{}] > ",
            if let Some(ref c) = self.context {
                self.styles.prompt_context(c.name.as_str())
            } else {
                self.styles.prompt_context("none")
            },
            if let Some(ref n) = self.namespace {
                self.styles.prompt_namespace(n.as_str())
            } else {
                self.styles.prompt_namespace("none")
            },
            match self.current_selection {
                ObjectSelection::Single(ref obj) =>
                    self.styles.prompt_object(obj.name.as_str(), obj.type_str()),
                ObjectSelection::Range(_) => self
                    .styles
                    .prompt_range(self.range_str.as_ref().unwrap().as_str()),
                ObjectSelection::None => self.styles.prompt_select_none("none"),
            }
        );
    }

    pub fn get_rustyline_conf(&self) -> rustyconfig::Config {
        self.click_config.get_rustyline_conf()
    }

    pub fn get_contexts(&self) -> &BTreeMap<String, crate::config::ContextConf> {
        &self.config.contexts
    }

    pub fn set_context(&mut self, ctx: Option<&str>) {
        if let Some(cname) = ctx {
            self.context = match self.config.get_context(cname, &self.click_config) {
                Ok(context) => Some(context),
                Err(e) => {
                    println!(
                        "[WARN] Couldn't find/load context {}, now no current context. \
                         Error: {}",
                        cname, e
                    );
                    None
                }
            };
            self.save_click_config();
            self.set_prompt();
        }
    }

    pub fn set_namespace(&mut self, namespace: Option<&str>) {
        let mut do_clear = false;
        if let (&Some(ref my_ns), Some(new_ns)) = (&self.namespace, namespace) {
            if my_ns.as_str() != new_ns {
                do_clear = true; // need to use bool since self is borrowed here
            }
        }
        if do_clear {
            self.clear_current();
        }
        self.namespace = namespace.map(|n| n.to_owned());
        self.set_prompt();
    }

    pub fn set_editor(&mut self, editor: Option<&str>) {
        self.click_config.editor = editor.map(|s| s.to_string());
    }

    pub fn set_terminal(&mut self, terminal: Option<&str>) {
        self.click_config.terminal = terminal.map(|s| s.to_string());
    }

    pub fn set_kubectl_binary(&mut self, kubectl_binary: Option<&str>) {
        self.click_config.kubectl_binary = kubectl_binary.map(|s| s.to_string());
    }

    pub fn set_completion_type(&mut self, comptype: config::CompletionType) {
        self.click_config.completiontype = comptype;
        self.need_new_editor = true;
    }

    pub fn set_edit_mode(&mut self, editmode: config::EditMode) {
        self.click_config.editmode = editmode;
        self.need_new_editor = true;
    }

    // Return the current position of the specified alias in the Vec, or None if it's not there
    fn alias_position(&self, alias: &str) -> Option<usize> {
        self.click_config
            .aliases
            .iter()
            .position(|a| a.alias == *alias)
    }

    // return the alias struct for the specified alias
    pub fn get_alias(&self, alias: &str) -> Option<&Alias> {
        self.alias_position(alias)
            .and_then(|p| self.click_config.aliases.get(p))
    }

    pub fn add_alias(&mut self, alias: Alias) {
        self.remove_alias(&alias.alias);
        self.click_config.aliases.push(alias);
        self.save_click_config();
    }

    pub fn remove_alias(&mut self, alias: &str) -> bool {
        match self.alias_position(alias) {
            Some(p) => {
                self.click_config.aliases.remove(p);
                self.save_click_config();
                true
            }
            None => false,
        }
    }

    pub fn set_last_objs<T: Into<Vec<KObj>>>(&mut self, objs: T) {
        self.last_objs = Some(objs.into());
    }

    pub fn clear_last_objs(&mut self) {
        self.last_objs = None;
    }

    pub fn clear_current(&mut self) {
        self.current_selection = ObjectSelection::None;
        self.range_str = None;
        self.set_prompt();
    }

    /// get the item from the last list at the specified index
    pub fn item_at(&self, index: usize) -> Option<&KObj> {
        self.last_objs.as_ref().and_then(|lo| lo.get(index))
    }

    pub fn set_current(&mut self, num: usize) {
        self.current_selection = match self.item_at(num) {
            Some(obj) => ObjectSelection::Single(obj.clone()),
            None => ObjectSelection::None,
        };
        self.range_str = None;
        self.set_prompt();
    }

    pub fn set_range(&mut self, range: Vec<KObj>) {
        let range_str = if range.is_empty() {
            "Empty range".to_string()
        } else {
            let mut r = format!("{} {}", range.len(), range.get(0).unwrap().type_str());
            if range.len() > 1 {
                r.push('s');
            }
            r.push_str(" selected");
            r
        };
        self.current_selection = ObjectSelection::Range(range);
        self.range_str = Some(range_str);
        self.set_prompt();
    }

    pub fn current_pod(&self) -> Option<&KObj> {
        match self.current_selection {
            ObjectSelection::Single(ref obj) => match obj.typ {
                ObjType::Pod { .. } => Some(obj),
                _ => None,
            },
            _ => None,
        }
    }

    // the function. print its error if an error happens. return true if the loop should continue,
    // false if it should stop
    fn call_selection_func<F>(
        obj: &KObj,
        writer: &mut ClickWriter,
        f: &mut F,
        continue_all: &mut bool,
    ) -> bool
    where
        F: FnMut(&KObj, &mut ClickWriter) -> Result<(), ClickError>,
    {
        if let Err(e) = f(obj, writer) {
            clickwriteln!(writer, "Error applying operation to {}: {}", obj.name, e);
            if *continue_all {
                return true;
            }
            clickwriteln!(writer, "  o = once: continue this time, ask again on error");
            clickwriteln!(writer, "  a = all: continue over all future errors");
            clickwriteln!(writer, "  n/N = no: abort range operation (default)");
            clickwrite!(writer, "Continue? [o/a/N]? ");
            io::stdout().flush().expect("Could not flush stdout");
            let mut conf = String::new();
            if io::stdin().read_line(&mut conf).is_ok() {
                match conf.trim() {
                    "o" | "once" => true,
                    "a" | "all" => {
                        *continue_all = true;
                        true
                    }
                    _ => false,
                }
            } else {
                clickwriteln!(writer, "Could not read response, stopping");
                false
            }
        } else {
            true
        }
    }

    // apply a function to each selected object.
    pub fn apply_to_selection<F>(
        &self,
        writer: &mut ClickWriter,
        sepfmt: Option<&str>,
        mut f: F,
    ) -> Result<(), ClickError>
    where
        F: FnMut(&KObj, &mut ClickWriter) -> Result<(), ClickError>,
    {
        match self.current_selection() {
            ObjectSelection::Single(obj) => f(obj, writer),
            ObjectSelection::Range(range) => {
                let mut continue_all = false;
                let mut go = true;
                for obj in range.iter() {
                    if !go {
                        return Err(ClickError::CommandError(
                            "Aborting range action".to_string(),
                        ));
                    }
                    if let Some(fmt) = sepfmt {
                        let mut fmtvars = HashMap::new();
                        fmtvars.insert("name".to_string(), obj.name());
                        fmtvars.insert(
                            "namespace".to_string(),
                            obj.namespace.as_deref().unwrap_or("[none]"),
                        );
                        match strfmt(fmt, &fmtvars) {
                            Ok(sep) => {
                                clickwriteln!(writer, "{}", sep);
                                go = Env::call_selection_func(
                                    obj,
                                    writer,
                                    &mut f,
                                    &mut continue_all,
                                );
                            }
                            Err(e) => {
                                clickwriteln!(
                                    writer,
                                    "-- format of separater for {} failed: {} --",
                                    obj.name(),
                                    e
                                );
                                go = Env::call_selection_func(
                                    obj,
                                    writer,
                                    &mut f,
                                    &mut continue_all,
                                );
                            }
                        }
                    } else {
                        go = Env::call_selection_func(obj, writer, &mut f, &mut continue_all);
                    }
                }
                Ok(())
            }
            ObjectSelection::None => Err(ClickError::CommandError(
                "No objects currently active".to_string(),
            )),
        }
    }

    pub fn run_on_context<F, R>(&self, f: F) -> Result<R, ClickError>
    where
        F: FnOnce(&crate::k8s::Context) -> Result<R, ClickError>,
    {
        match self.context {
            Some(ref c) => f(c),
            None => Err(ClickError::CommandError("No active context".to_string())),
        }
    }

    /// Add a new task for the env to keep track of
    pub fn add_port_forward(&mut self, pf: PortForward) {
        self.port_forwards.push(pf);
    }

    pub fn get_port_forwards(&mut self) -> std::slice::IterMut<PortForward> {
        self.port_forwards.iter_mut()
    }

    pub fn get_port_forward(&mut self, i: usize) -> Option<&mut PortForward> {
        self.port_forwards.get_mut(i)
    }

    pub fn stop_port_forward(&mut self, i: usize) -> Result<(), std::io::Error> {
        if i < self.port_forwards.len() {
            let mut pf = self.port_forwards.remove(i);
            pf.child.kill()
        } else {
            Ok(())
        }
    }

    pub fn stop_all_forwards(&mut self) {
        for pf in self.port_forwards.iter_mut() {
            pf.child.kill().unwrap();
        }
        self.port_forwards = Vec::new();
    }

    /// Try and expand alias.
    /// This function looks at the first word (whitespace delimited) of the
    /// line, checks if it matches an alias, if it does it returns and ExpandedAlias with the
    /// expansion and the rest of the line, otherwise the expansion field will be None and rest will
    /// contain the whole line
    pub fn try_expand_alias<'a>(
        &'a self,
        line: &'a str,
        prev_word: Option<&'a str>,
    ) -> ExpandedAlias<'a> {
        let pos = line.find(char::is_whitespace).unwrap_or(line.len());
        let word = &line[0..pos];
        // don't expand if prev_word is Some, and is equal to my word
        // this means an alias maps to itself, and we want to stop expanding
        // to avoid an infinite loop
        if prev_word.filter(|pw| *pw == word).is_none() {
            for alias in self.click_config.aliases.iter() {
                if word == alias.alias.as_str() {
                    return ExpandedAlias {
                        expansion: Some(alias),
                        rest: &line[pos..],
                    };
                }
            }
        }
        ExpandedAlias {
            expansion: None,
            rest: line,
        }
    }
}

impl fmt::Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let kubectl_binary = self
            .click_config
            .kubectl_binary
            .as_deref()
            .unwrap_or("kubectl");
        let kubectl_path = std::process::Command::new("which")
            .arg(kubectl_binary)
            .output()
            .map(|output| {
                if output.status.success() {
                    std::str::from_utf8(&output.stdout)
                        .unwrap_or("Failed to parse 'which' output")
                        .to_string()
                } else if kubectl_binary.starts_with('/') {
                    format!("{} not found. Does it exist?", kubectl_binary)
                } else {
                    format!("{} not found. Is it in your PATH?", kubectl_binary)
                }
            })
            .unwrap_or_else(|e| {
                format!(
                    "Error searching for kubectl_binary (which is set to {}): {}",
                    kubectl_binary, e
                )
            });
        write!(
            f,
            "Env {{
  Current Context: {}
  Availble Contexts: {:?}
  Kubernetes Config File(s): {}
  Completion Type: {}
  Edit Mode: {}
  Editor: {}
  Terminal: {}
  kubectl Binary: {}
  Range Separator: {}
  Describe Shows Events: {}
}}",
            if let Some(ref c) = self.context {
                self.styles.config_val(c.name.as_str())
            } else {
                self.styles.config_val("none")
            },
            self.config.contexts.keys(),
            self.styles.config_val(self.config.source_file.as_str()),
            {
                let ctstr: String = (&self.click_config.completiontype).into();
                self.styles.config_val_string(ctstr)
            },
            {
                let emstr: String = (&self.click_config.editmode).into();
                self.styles.config_val_string(emstr)
            },
            self.styles.config_val(
                self.click_config
                    .editor
                    .as_deref()
                    .unwrap_or("<unset, will use $EDITOR>")
            ),
            self.styles.config_val(
                self.click_config
                    .terminal
                    .as_deref()
                    .unwrap_or("<unset, will use xterm>")
            ),
            self.styles.config_val(&kubectl_path),
            self.styles
                .config_val(self.click_config.range_separator.as_str()),
            self.styles.config_val(
                self.click_config
                    .describe_include_events
                    .to_string()
                    .as_str()
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::get_test_config;

    #[test]
    fn try_expand_alias() {
        let mut cc = ClickConfig::default();
        let pn_alias = Alias {
            alias: "pn".to_string(),
            expanded: "pods --sort node".to_string(),
        };
        let x_alias = Alias {
            alias: "x".to_string(),
            expanded: "xpand".to_string(),
        };
        cc.aliases.push(pn_alias.clone());
        cc.aliases.push(x_alias.clone());
        let env = Env::new(get_test_config(), cc, PathBuf::from("/tmp/click.config"));

        let exp1 = env.try_expand_alias("pn", None);
        assert_eq!(exp1.expansion, Some(&pn_alias));
        assert_eq!(exp1.rest, "");

        let exp2 = env.try_expand_alias("x", None);
        assert_eq!(exp2.expansion, Some(&x_alias));
        assert_eq!(exp2.rest, "");

        let exp2 = env.try_expand_alias("x rest is this", None);
        assert_eq!(exp2.expansion, Some(&x_alias));
        assert_eq!(exp2.rest, " rest is this");

        let exp3 = env.try_expand_alias("no alias", None);
        assert_eq!(exp3.expansion, None);
        assert_eq!(exp3.rest, "no alias");

        let exp4 = env.try_expand_alias("x", Some("x"));
        assert_eq!(exp4.expansion, None);
        assert_eq!(exp4.rest, "x");
    }
}
