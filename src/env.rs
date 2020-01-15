use config::{self, Alias, ClickConfig, Config};
use error::KubeError;
use kube::{
    ConfigMapList, DeploymentList, JobList, Kluster, NodeList, PodList, ReplicaSetList, SecretList,
    ServiceList, StatefulSetList,
};
use values::val_str_opt;

use ansi_term::Colour::{Black, Blue, Cyan, Green, Purple, Red, Yellow};
use rustyline::config as rustyconfig;
use tempdir::TempDir;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};


/// An object we can have as a "current" thing
#[derive(Debug, PartialEq)]
pub enum KObj {
    None,
    Pod {
        name: String,
        containers: Vec<String>,
    },
    Node(String),
    Deployment(String),
    Service(String),
    ReplicaSet(String),
    StatefulSet(String),
    ConfigMap(String),
    Secret(String),
    Job(String),
}

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

/// Keep track of our repl environment
pub struct Env {
    pub config: Config,
    pub click_config: ClickConfig,
    click_config_path: PathBuf,
    pub quit: bool,
    pub need_new_editor: bool,
    pub kluster: Option<Kluster>,
    pub namespace: Option<String>,
    pub current_object: KObj,
    pub current_object_namespace: Option<String>,
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
        }).expect("Error setting Ctrl-C handler");
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
            current_object: KObj::None,
            current_object_namespace: None,
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
            match self.current_object {
                KObj::None => Yellow.paint("none"),
                KObj::Pod { ref name, .. } => Yellow.bold().paint(name.as_str()),
                KObj::Node(ref name) => Blue.bold().paint(name.as_str()),
                KObj::Deployment(ref name) => Purple.bold().paint(name.as_str()),
                KObj::Service(ref name) => Cyan.bold().paint(name.as_str()),
                KObj::ReplicaSet(ref name) => Green.bold().paint(name.as_str()),
                KObj::StatefulSet(ref name) => Green.bold().paint(name.as_str()),
                KObj::ConfigMap(ref name) => Black.bold().paint(name.as_str()),
                KObj::Secret(ref name) => Red.bold().paint(name.as_str()),
                KObj::Job(ref name) => Purple.bold().paint(name.as_str()),
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
        self.current_object = KObj::None;
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
                    self.current_object = KObj::Pod {
                        name: pod.metadata.name.clone(),
                        containers,
                    };
                    self.current_object_namespace = pod.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::NodeList(ref nl) => {
                if let Some(name) = nl.items.get(num).map(|n| n.metadata.name.clone()) {
                    self.current_object = KObj::Node(name);
                    self.current_object_namespace = None;
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::DeploymentList(ref dl) => {
                if let Some(dep) = dl.items.get(num) {
                    self.current_object = KObj::Deployment(dep.metadata.name.clone());
                    self.current_object_namespace = dep.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::ServiceList(ref sl) => {
                if let Some(service) = sl.items.get(num) {
                    self.current_object = KObj::Service(service.metadata.name.clone());
                    self.current_object_namespace = service.metadata.namespace.clone();
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::ReplicaSetList(ref rsl) => {
                if let Some(ref replicaset) = rsl.items.get(num) {
                    match val_str_opt("/metadata/name", replicaset) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", replicaset);
                            self.current_object = KObj::ReplicaSet(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("ReplicaSet has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::StatefulSetList(ref stfs) => {
                if let Some(ref statefulset) = stfs.items.get(num) {
                    match val_str_opt("/metadata/name", statefulset) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", statefulset);
                            self.current_object = KObj::StatefulSet(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("StatefulSet has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::ConfigMapList(ref cml) => {
                if let Some(ref cm) = cml.items.get(num) {
                    match val_str_opt("/metadata/name", cm) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", cm);
                            self.current_object = KObj::ConfigMap(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("ConfigMap has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::SecretList(ref sl) => {
                if let Some(ref secret) = sl.items.get(num) {
                    match val_str_opt("/metadata/name", secret) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", secret);
                            self.current_object = KObj::Secret(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("Secret has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
            LastList::JobList(ref jl) => {
                if let Some(ref job) = jl.items.get(num) {
                    match val_str_opt("/metadata/name", job) {
                        Some(name) => {
                            let namespace = val_str_opt("/metadata/namespace", job);
                            self.current_object = KObj::Job(name);
                            self.current_object_namespace = namespace;
                        }
                        None => {
                            println!("Job has no name in metadata");
                            self.current_object = KObj::None;
                        }
                    }
                } else {
                    self.current_object = KObj::None;
                }
            }
        }
        self.set_prompt();
    }

    pub fn current_pod(&self) -> Option<&String> {
        if let KObj::Pod { ref name, .. } = self.current_object {
            Some(name)
        } else {
            None
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
    /// FFIX Returns Some(expanded) if the alias expands, or None if no such alias
    /// is found
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
