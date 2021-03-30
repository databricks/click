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

// build check

//! The Command Line Interactive Contoller for Kubernetes

#[macro_use]
extern crate duct;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate prettytable;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
mod output;

extern crate ansi_term;
extern crate atomicwrites;
extern crate base64;
extern crate chrono;
#[macro_use]
extern crate clap;
extern crate ctrlc;
extern crate der_parser;
extern crate dirs;
extern crate duct_sh;
extern crate humantime;
extern crate hyper;
extern crate hyper_sync_rustls;
extern crate log;
extern crate os_pipe;
extern crate regex;
extern crate ring;
extern crate rustls;
extern crate rustyline;
extern crate serde;
extern crate serde_yaml;
extern crate strfmt;
extern crate tempdir;
extern crate term;
extern crate untrusted;
extern crate webpki;

mod certs;
mod cmd;
mod command_processor;
mod completer;
mod config;
mod connector;
mod describe;
mod env;
mod error;
mod kobj;
mod kube;
mod parser;
mod subjaltnames;
mod table;
mod values;

#[cfg(test)]
mod duct_mock;

use clap::{App, Arg};

use std::path::PathBuf;

use command_processor::CommandProcessor;
use config::{ClickConfig, Config};
use env::Env;

use output::ClickWriter;

fn main() {
    env_logger::init();
    // Command line arg parsing for click itself
    let matches = App::new("Click")
        .version(crate_version!())
        .author("Nick Lanham <nick@databricks.com>")
        .about("Command Line Interactive Contoller for Kubernetes")
        .arg(
            Arg::with_name("config_dir")
                .short("c")
                .long("config_dir")
                .value_name("DIR")
                .help("Specify the directory to find kubernetes and click configs")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("exec")
                .long("exec")
                .value_name("COMMAND")
                .help("Execute the specified command then exit")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("context")
                .short("C")
                .long("context")
                .help("Start in the specified context")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("namespace")
                .short("n")
                .long("namespace")
                .help("Start in the specified namespace")
                .takes_value(true),
        )
        .get_matches();

    let conf_dir = if let Some(dir) = matches.value_of("config_dir") {
        PathBuf::from(dir)
    } else {
        match dirs::home_dir() {
            Some(mut path) => {
                path.push(".kube");
                path
            }
            None => {
                println!("Can't get your home dir, please specify --config_dir");
                std::process::exit(-2);
            }
        }
    };

    let mut click_path = conf_dir.clone();
    click_path.push("click.config");
    let click_conf = match ClickConfig::from_file(click_path.as_path().to_str().unwrap()) {
        Ok(conf) => conf,
        Err(e) => {
            println!("Could not load click config: {}\nUsing default values.", e);
            ClickConfig::default()
        }
    };

    let config_paths = std::env::var_os("KUBECONFIG")
        .map(|paths| {
            let split_paths = std::env::split_paths(&paths);
            split_paths.collect::<Vec<PathBuf>>()
        })
        .unwrap_or_else(|| {
            let mut config_path = conf_dir.clone();
            config_path.push("config");
            vec![config_path]
        })
        .into_iter()
        .map(|config_file| {
            config_file
                .as_path()
                .to_str()
                .unwrap_or("[CONFIG_PATH_EMPTY]")
                .to_owned()
        })
        .collect::<Vec<_>>();

    let config = match Config::from_files(&config_paths) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "Could not load kubernetes config. Cannot continue.  Error was: {}",
                e
            );
            return;
        }
    };

    let mut hist_path = conf_dir;
    hist_path.push("click.history");

    let mut env = Env::new(config, click_conf, click_path);
    if let Some(context) = matches.value_of("context") {
        env.set_context(Some(context));
    }
    if let Some(namespace) = matches.value_of("namespace") {
        env.set_namespace(Some(namespace));
    }

    let mut processor = CommandProcessor::new(env, hist_path);
    if let Some(command) = matches.value_of("exec") {
        let writer = ClickWriter::new();
        processor.process_line(command, writer);
    } else {
        processor.run_repl();
    }
}
