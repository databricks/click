use config::{self, Alias, ClickConfig, Config};
use error::KubeError;
use kobj::{KObj, ObjType};
use kube::{
    ConfigMapList, DeploymentList, JobList, Kluster, NodeList, PodList, ReplicaSetList, SecretList,
    ServiceList, StatefulSetList,
};

use ansi_term::Colour::{Green, Red, Yellow};
use rustyline::config as rustyconfig;
use tempdir::TempDir;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub enum LastList {
    None,
    PodList(PodList),
    NodeList(NodeList),
    DeploymentList(DeploymentList),
    ServiceList(ServiceList),
    ReplicaSetList(ReplicaSetList),
    StatefulSetList(StatefulSetList),
    ConfigMapList(ConfigMapList),
    SecretList(SecretList),
    JobList(JobList),
}

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
    click_config_path: PathBuf,
    pub quit: bool,
    pub need_new_editor: bool,
    pub kluster: Option<Kluster>,
    pub namespace: Option<String>,
    current_selection: ObjectSelection,
    last_objs: LastList,
    pub ctrlcbool: Arc<AtomicBool>,
    port_forwards: Vec<PortForward>,
    pub prompt: String,
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
        let mut env = Env {
            config,
            click_config,
            click_config_path,
            quit: false,
            need_new_editor: false,
            kluster: None,
            namespace,
            current_selection: ObjectSelection::None,
            last_objs: LastList::None,
            ctrlcbool: CTC_BOOL.clone(),
            port_forwards: Vec::new(),
            prompt: format!(
                "[{}] [{}] [{}] > ",
                Red.paint("none"),
                Green.paint("none"),
                Yellow.paint("none")
            ),
            tempdir: TempDir::new("click"),
        };
        env.set_context(context.as_ref().map(|x| &**x));
        env
    }

    pub fn current_selection(&self) -> &ObjectSelection {
        &self.current_selection
    }

    pub fn save_click_config(&mut self) {
        self.click_config.namespace = self.namespace.clone();
        self.click_config.context = self.kluster.as_ref().map(|k| k.name.clone());
        self.click_config
            .save_to_file(self.click_config_path.as_path().to_str().unwrap())
            .unwrap();
    }

    // sets the prompt string based on current settings
    fn set_prompt(&mut self) {
        self.prompt = format!(
            "[{}] [{}] [{}] > ",
            if let Some(ref k) = self.kluster {
                Red.bold().paint(k.name.as_str())
            } else {
                Red.paint("none")
            },
            if let Some(ref n) = self.namespace {
                Green.bold().paint(n.as_str())
            } else {
                Green.paint("none")
            },
            match self.current_selection {
                ObjectSelection::Single(ref obj) => obj.prompt_str(),
                ObjectSelection::Range(_) => Yellow.paint("A RANGE!"),
                ObjectSelection::None => Yellow.paint("none"),
            }
        );
    }

    pub fn get_rustyline_conf(&self) -> rustyconfig::Config {
        self.click_config.get_rustyline_conf()
    }

    pub fn get_contexts(&self) -> &HashMap<String, ::config::ContextConf> {
        &self.config.contexts
    }

    pub fn set_context(&mut self, ctx: Option<&str>) {
        if let Some(cname) = ctx {
            self.kluster = match self.config.cluster_for_context(cname) {
                Ok(k) => Some(k),
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

    pub fn set_editor(&mut self, editor: &Option<String>) {
        self.click_config.editor = editor.clone();
    }

    pub fn set_terminal(&mut self, terminal: &Option<String>) {
        self.click_config.terminal = terminal.clone();
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

    pub fn set_lastlist(&mut self, list: LastList) {
        self.last_objs = list;
    }

    pub fn clear_current(&mut self) {
        self.current_selection = ObjectSelection::None;
        self.set_prompt();
    }

    pub fn set_current(&mut self, num: usize) {
        match self.last_objs {
            LastList::None => {
                println!("No active object list");
            }
            LastList::PodList(ref pl) => {
                if let Some(pod) = pl.items.get(num) {
                    let containers = pod
                        .spec
                        .containers
                        .iter()
                        .map(|cspec| cspec.name.clone())
                        .collect();
                    self.current_selection = ObjectSelection::Single(
                        KObj::from_metadata(&pod.metadata, ObjType::Pod { containers })
                    );
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::NodeList(ref nl) => {
                if let Some(name) = nl.items.get(num).map(|n| n.metadata.name.clone()) {
                    self.current_selection = ObjectSelection::Single(
                        KObj {
                            name,
                            namespace: None,
                            typ: ObjType::Node
                        }
                    );
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::DeploymentList(ref dl) => {
                if let Some(dep) = dl.items.get(num) {
                    self.current_selection = ObjectSelection::Single(
                        KObj::from_metadata(&dep.metadata, ObjType::Deployment)
                    );
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::ServiceList(ref sl) => {
                if let Some(service) = sl.items.get(num) {
                    self.current_selection = ObjectSelection::Single(
                        KObj::from_metadata(&service.metadata, ObjType::Service)
                    );
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::ReplicaSetList(ref rsl) => {
                if let Some(ref replicaset) = rsl.items.get(num) {
                    match KObj::from_value(replicaset, ObjType::ReplicaSet) {
                        Some(obj) => {
                            self.current_selection = ObjectSelection::Single(obj)
                        }
                        None => {
                            println!("ReplicaSet has no name in metadata");
                            self.current_selection = ObjectSelection::None;
                        }
                    }
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::StatefulSetList(ref stfs) => {
                if let Some(ref statefulset) = stfs.items.get(num) {
                    match KObj::from_value(statefulset, ObjType::StatefulSet) {
                        Some(obj) => {
                            self.current_selection = ObjectSelection::Single(obj)
                        }
                        None => {
                            println!("StatefulSet has no name in metadata");
                            self.current_selection = ObjectSelection::None;
                        }
                    }
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::ConfigMapList(ref cml) => {
                if let Some(ref cm) = cml.items.get(num) {
                       match KObj::from_value(cm, ObjType::ConfigMap) {
                        Some(obj) => {
                            self.current_selection = ObjectSelection::Single(obj)
                        }
                        None => {
                            println!("ConfigMap has no name in metadata");
                            self.current_selection = ObjectSelection::None;
                        }
                    }
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::SecretList(ref sl) => {
                if let Some(ref secret) = sl.items.get(num) {
                    match KObj::from_value(secret, ObjType::Secret) {
                        Some(obj) => {
                            self.current_selection = ObjectSelection::Single(obj)
                        }
                        None => {
                            println!("Secret has no name in metadata");
                            self.current_selection = ObjectSelection::None;
                        }
                    }
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
            LastList::JobList(ref jl) => {
                if let Some(ref job) = jl.items.get(num) {
                    match KObj::from_value(job, ObjType::Job) {
                        Some(obj) => {
                            self.current_selection = ObjectSelection::Single(obj)
                        }
                        None => {
                            println!("Job has no name in metadata");
                            self.current_selection = ObjectSelection::None;
                        }
                    }
                } else {
                    self.current_selection = ObjectSelection::None;
                }
            }
        }
        self.set_prompt();
    }

    pub fn current_pod(&self) -> Option<&KObj> {
        match self.current_selection {
            ObjectSelection::Single(ref obj) => {
                match obj.typ {
                    ObjType::Pod { .. } => Some(obj),
                    _ => None,
                }
            }
            _ => None
        }
    }

    pub fn run_on_kluster<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Kluster) -> Result<R, KubeError>,
    {
        match self.kluster {
            Some(ref k) => match f(k) {
                Ok(r) => Some(r),
                Err(e) => {
                    println!("{}", e);
                    None
                }
            },
            None => {
                println!("Need to have an active context");
                None
            }
        }
    }

    /// Add a new task for the env to keep track of
    pub fn add_port_forward(&mut self, pf: PortForward) {
        self.port_forwards.push(pf);
    }

    pub fn get_port_forwards(&self) -> std::slice::Iter<PortForward> {
        self.port_forwards.iter()
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
        let pos = line.find(char::is_whitespace).unwrap_or_else(|| line.len());
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
}}",
            if let Some(ref k) = self.kluster {
                Green.bold().paint(k.name.as_str())
            } else {
                Green.paint("none")
            },
            self.config.contexts.keys(),
            Green.paint(&self.config.source_file),
            {
                let ctstr: String = (&self.click_config.completiontype).into();
                Green.paint(ctstr)
            },
            {
                let emstr: String = (&self.click_config.editmode).into();
                Green.paint(emstr)
            },
            Green.paint(
                self.click_config
                    .editor
                    .as_ref()
                    .unwrap_or(&"<unset, will use $EDITOR>".to_owned())
            ),
            Green.paint(
                self.click_config
                    .terminal
                    .as_ref()
                    .unwrap_or(&"<unset, will use xterm>".to_owned())
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::get_test_config;

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
