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

/// Module to handle writing data to stdout, and/or copying/writing it
/// to files etc

use std::error::Error;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use ::error::KubeError;

/// Ignore write errors (for now) TODO: What to do with them?
macro_rules! clickwrite {
    ($writer:expr) => {
        write!($writer);
    };
    ($writer:expr, $fmt:expr) => {
        match write!($writer, $fmt) {
            Ok(_) => {},
            Err(_) => {},
        }
    };

    ($writer:expr, $fmt:expr, $($arg:tt)*) => {
        match write!($writer, $fmt, $($arg)*) {
            Ok(_) => {},
            Err(_) => {},
        }
    };
}

pub struct ClickWriter {
    pub out_file: Option<File>,
    pub pipe_proc: Option<Child>,
}

impl ClickWriter {
    pub fn new() -> ClickWriter {
        ClickWriter {
            out_file: None,
            pipe_proc: None,
        }
    }

    pub fn setup_pipe(&mut self, cmd: &str) -> Result<(), KubeError> {
        let mut parts = cmd.split_whitespace();
        match parts.next() {
            Some(cmdstr) => {
                match Command::new(cmdstr)
                    .args(parts)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn() {
                        Ok(process) => {
                            self.pipe_proc = Some(process);
                            Ok(())
                        }
                        Err(e) => {
                            Err(KubeError::from(e))
                        }
                    }
            }
            None => {
                Err(KubeError::PipeErr("Empty pipe command".to_owned()))
            }
        }
    }

    pub fn finish_output(&mut self) {
        if let Some(ref mut child) = self.pipe_proc {
            {
                child.stdin.take(); // force the drop
            }
            let mut s = String::new();
            match child.stdout.as_mut().unwrap().read_to_string(&mut s) {
                Ok(_) => print!("{}", s),
                Err(why) => println!("Failed to read pipe output: {}",
                                     why.description()),
            }
        }
        self.out_file = None;
        self.pipe_proc = None;
    }
}

impl Write for ClickWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if let Some(ref mut file) = self.out_file {
            file.write(buf)
        }
        else if let Some(ref mut child) = self.pipe_proc {
            child.stdin.as_mut().unwrap().write(buf)
        } else {
            io::stdout().write(buf)
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut file) = self.out_file {
            file.flush()
        }
        else if let Some(ref mut child) = self.pipe_proc {
            child.stdin.as_mut().unwrap().flush()
        } else {
            io::stdout().flush()
        }
    }
}
