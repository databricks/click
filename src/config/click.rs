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

/// Click config
use atomicwrites::{AllowOverwrite, AtomicFile};
use rustyline::config as rustyconfig;

use std::fmt;
use std::fs::File;
use std::io::Read;

use crate::error::ClickError;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Alias {
    pub alias: String,
    pub expanded: String,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub enum EditMode {
    Emacs,
    Vi,
}

impl Default for EditMode {
    fn default() -> Self {
        EditMode::Emacs
    }
}

impl fmt::Display for EditMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EditMode::Emacs => "Emacs",
                EditMode::Vi => "Vi",
            }
        )
    }
}

impl From<&EditMode> for String {
    fn from(e: &EditMode) -> String {
        format!("{}", e)
    }
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub enum CompletionType {
    Circular,
    List,
}

impl Default for CompletionType {
    fn default() -> Self {
        CompletionType::Circular
    }
}

impl fmt::Display for CompletionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CompletionType::Circular => "Circular",
                CompletionType::List => "List",
            }
        )
    }
}

impl From<&CompletionType> for String {
    fn from(ct: &CompletionType) -> String {
        format!("{}", ct)
    }
}

fn default_range_sep() -> String {
    "--- {name} ---".to_string()
}

fn default_connect_timeout() -> u32 {
    10
}

fn default_read_timeout() -> u32 {
    20
}

fn default_describe_include_events() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClickConfig {
    pub namespace: Option<String>,
    pub context: Option<String>,
    pub editor: Option<String>,
    pub terminal: Option<String>,
    #[serde(default = "EditMode::default")]
    pub editmode: EditMode,
    #[serde(default = "CompletionType::default")]
    pub completiontype: CompletionType,
    #[serde(default = "Vec::new")]
    pub aliases: Vec<Alias>,
    #[serde(default = "default_range_sep")]
    pub range_separator: String,

    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u32,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u32,

    #[serde(default = "default_describe_include_events")]
    pub describe_include_events: bool,
}

impl Default for ClickConfig {
    fn default() -> ClickConfig {
        ClickConfig {
            namespace: None,
            context: None,
            editor: None,
            terminal: None,
            editmode: EditMode::default(),
            completiontype: CompletionType::default(),
            aliases: vec![],
            range_separator: default_range_sep(),
            connect_timeout_secs: default_connect_timeout(),
            read_timeout_secs: default_read_timeout(),
            describe_include_events: true,
        }
    }
}

impl ClickConfig {
    pub fn from_reader<R>(r: R) -> Result<ClickConfig, ClickError>
    where
        R: Read,
    {
        serde_yaml::from_reader(r).map_err(ClickError::from)
    }

    pub fn from_file(path: &str) -> Result<ClickConfig, ClickError> {
        let f = File::open(path)?;
        ClickConfig::from_reader(f)
    }

    pub fn get_rustyline_conf(&self) -> rustyconfig::Config {
        let mut config = rustyconfig::Builder::new();
        config = match self.editmode {
            EditMode::Emacs => config.edit_mode(rustyconfig::EditMode::Emacs),
            EditMode::Vi => config.edit_mode(rustyconfig::EditMode::Vi),
        };
        config = match self.completiontype {
            CompletionType::Circular => {
                config.completion_type(rustyconfig::CompletionType::Circular)
            }
            CompletionType::List => config.completion_type(rustyconfig::CompletionType::List),
        };
        config.build()
    }

    /// Save this config to specified path.  It's safe to call this from multiple running instances
    /// of Click, since we use an AtomicFile
    pub fn save_to_file(&self, path: &str) -> Result<(), ClickError> {
        let af = AtomicFile::new(path, AllowOverwrite);
        af.write(|mut f| serde_yaml::to_writer(&mut f, &self))
            .map_err(|e| {
                ClickError::ConfigFileError(format!("Failed to write config file: {}", e))
            })?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    static TEST_CONFIG: &str = r"---
namespace: ns
context: ctx
editor: emacs
terminal: alacritty -e
editmode: Vi
completiontype: List
aliases:
  - alias: pn
    expanded: pods --sort node";

    pub fn get_parsed_test_click_config() -> ClickConfig {
        ClickConfig::from_reader(TEST_CONFIG.as_bytes()).unwrap()
    }

    #[test]
    fn test_parse_config() {
        let config = ClickConfig::from_reader(TEST_CONFIG.as_bytes());
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.namespace, Some("ns".to_owned()));
        assert_eq!(config.context, Some("ctx".to_owned()));
        assert_eq!(config.editor, Some("emacs".to_owned()));
        assert_eq!(config.terminal, Some("alacritty -e".to_owned()));
        assert_eq!(config.editmode, EditMode::Vi);
        assert_eq!(config.completiontype, CompletionType::List);
        assert_eq!(config.aliases.len(), 1);
        assert_eq!(config.range_separator, default_range_sep());
        let a = config.aliases.get(0).unwrap();
        assert_eq!(a.alias, "pn");
        assert_eq!(a.expanded, "pods --sort node");
        assert_eq!(config.connect_timeout_secs, default_connect_timeout());
        assert_eq!(config.read_timeout_secs, default_read_timeout());
    }

    #[test]
    fn test_default_config() {
        let config = ClickConfig::default();
        assert_eq!(config.namespace, None);
        assert_eq!(config.editmode, EditMode::Emacs);
        assert_eq!(config.completiontype, CompletionType::Circular);
        assert_eq!(config.read_timeout_secs, default_read_timeout());
        assert_eq!(config.connect_timeout_secs, default_connect_timeout());
        assert_eq!(config.range_separator, default_range_sep());
    }

    #[test]
    fn test_invalid_conf() {
        let config = ClickConfig::from_reader("not valid".as_bytes());
        assert!(config.is_err());
    }

    #[test]
    fn test_rustline_conf() {
        let config = ClickConfig::from_reader(TEST_CONFIG.as_bytes());
        assert!(config.is_ok());
        let rlconf = config.unwrap().get_rustyline_conf();
        assert_eq!(
            rlconf.completion_type(),
            rustyline::config::CompletionType::List
        );
        assert_eq!(rlconf.edit_mode(), rustyline::config::EditMode::Vi);
        let rlconf = ClickConfig::default().get_rustyline_conf();
        assert_eq!(
            rlconf.completion_type(),
            rustyline::config::CompletionType::Circular
        );
        assert_eq!(rlconf.edit_mode(), rustyline::config::EditMode::Emacs);
    }
}
