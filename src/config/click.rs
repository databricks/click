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

use atomicwrites::{AtomicFile, AllowOverwrite};
use rustyline::config as rustyconfig;

use std::error::Error;
use std::fmt;
use std::fs::File;

use error::KubeError;

#[derive(Debug, Deserialize, Serialize)]
pub struct Alias {
    pub alias: String,
    pub expanded: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum EditMode {
    Emacs,
    Vi,
}

impl Default for EditMode {
    fn default() -> Self { EditMode::Emacs }
}

impl fmt::Display for EditMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            EditMode::Emacs => "Emacs",
            EditMode::Vi => "Vi",
        })
    }
}

impl Into<String> for &EditMode {
    fn into(self) -> String {
        format!("{}", self)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CompletionType {
    Circular,
    List,
}

impl Default for CompletionType {
    fn default() -> Self { CompletionType::Circular }
}

impl fmt::Display for CompletionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            CompletionType::Circular => "Circular",
            CompletionType::List => "List",
        })
    }
}

impl Into<String> for &CompletionType {
    fn into(self) -> String {
        format!("{}", self)
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
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
}

impl ClickConfig {
    pub fn from_file(path: &str) -> ClickConfig {
        match File::open(path) {
            Ok(f) => match serde_yaml::from_reader(f) {
                Ok(c) => c,
                Err(e) => {
                    println!("Could not read config file {:?}, using default values", e);
                    ClickConfig::default()
                }
            },
            Err(e) => {
                println!(
                    "Could not open config file at '{}': {}. Using default values",
                    path, e
                );
                ClickConfig::default()
            }
        }
    }

    pub fn get_rustyline_conf(&self) -> rustyconfig::Config {
        let mut config = rustyconfig::Builder::new();
        config = match self.editmode {
            EditMode::Emacs => config.edit_mode(rustyconfig::EditMode::Emacs),
            EditMode::Vi => config.edit_mode(rustyconfig::EditMode::Vi),
        };
        config = match self.completiontype {
            CompletionType::Circular =>
                config.completion_type(rustyconfig::CompletionType::Circular),
            CompletionType::List =>
                config.completion_type(rustyconfig::CompletionType::List),
        };
        config.build()
    }

    /// Save this config to specified path.  It's safe to call this from multiple running instances
    /// of Click, since we use an AtomicFile
    pub fn save_to_file(&self, path: &str) -> Result<(), KubeError> {
        let af = AtomicFile::new(path, AllowOverwrite);
        try!(af.write(|mut f| {
            serde_yaml::to_writer(&mut f, &self)
        }).map_err(|e| KubeError::ConfigFileError(
            format!("Failed to write config file: {}", e.description())
        )));
        Ok(())
    }
}
