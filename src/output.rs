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
use ansi_term::Colour::{Blue, Green};
use duct::Handle;
use duct_sh::sh_dangerous;
use os_pipe::{pipe, PipeWriter};
use serde::ser::Serialize;
use serde_json;
use serde_json::ser::{CharEscape, Formatter, PrettyFormatter, Serializer};
use serde_json::Error as JsonError;
use serde_yaml;

use std::fs::File;
use std::io;
use std::io::{Stdout, Write};

use error::KubeError;

/// Ignore write errors (for now) TODO: What to do with them?
macro_rules! clickwrite {
    ($writer:expr) => {
        write!($writer);
    };
    ($writer:expr, $fmt:expr) => {
        if write!($writer, $fmt).is_ok() {}
    };

    ($writer:expr, $fmt:expr, $($arg:tt)*) => {
        if write!($writer, $fmt, $($arg)*).is_ok() {}
    };
}

macro_rules! clickwriteln {
    ($writer:expr) => {
        writeln!($writer);
    };
    ($writer:expr, $fmt:expr) => {
        if writeln!($writer, $fmt).is_ok() {}
    };

    ($writer:expr, $fmt:expr, $($arg:tt)*) => {
        if writeln!($writer, $fmt, $($arg)*).is_ok() {}
    };
}

struct PipeProc {
    pipe: PipeWriter,
    expr: Handle,
}

impl PipeProc {
    fn finish(self) -> io::Result<String> {
        drop(self.pipe);
        let output = self.expr.into_output()?;
        String::from_utf8(output.stdout).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pipe.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pipe.flush()
    }
}

enum WriterOutput {
    Stdout(Stdout),
    #[allow(dead_code)] // used in test
    Buffer(Vec<u8>),
    File(File),
    Pipe(Box<PipeProc>),
}

pub struct ClickWriter {
    output: WriterOutput,
}

impl ClickWriter {
    pub fn new() -> ClickWriter {
        ClickWriter {
            output: WriterOutput::Stdout(std::io::stdout()),
        }
    }

    #[allow(dead_code)] // used in test
    pub fn with_buffer(buffer: Vec<u8>, _do_color: bool) -> ClickWriter {
        ClickWriter {
            output: WriterOutput::Buffer(buffer),
        }
    }

    pub fn set_output_file(&mut self, file: File) {
        self.output = WriterOutput::File(file);
    }

    pub fn setup_pipe(&mut self, cmd: &str) -> Result<(), KubeError> {
        let expr = sh_dangerous(cmd);
        let (pipe_read, pipe_write) = pipe()?;
        let handle = expr.stdin_file(pipe_read).start()?;
        self.output = WriterOutput::Pipe(Box::new(PipeProc {
            pipe: pipe_write,
            expr: handle,
        }));
        Ok(())
    }

    pub fn finish_output(self) -> Option<Vec<u8>> {
        match self.output {
            WriterOutput::Pipe(pipe_proc) => {
                match pipe_proc.finish() {
                    Ok(out) => {
                        print!("{}", out);
                    }
                    Err(e) => {
                        eprint!("Failed to execute command: {}", e);
                    }
                }
                None
            }
            WriterOutput::Buffer(buffer) => Some(buffer),
            _ => None,
        }
    }

    pub fn pretty_color_json<T: ?Sized>(&mut self, value: &T) -> Result<(), JsonError>
    where
        T: Serialize,
    {
        if let WriterOutput::Stdout(_) = self.output {
            let mut ser = Serializer::with_formatter(self, PrettyColorFormatter::new());
            value.serialize(&mut ser)
        } else {
            // don't do color if we're piping/redirecting
            serde_json::to_writer(self, value)
        }
    }

    pub fn print_yaml<T: ?Sized>(&mut self, value: &T) -> Result<(), serde_yaml::Error>
    where
        T: Serialize,
    {
        serde_yaml::to_writer(self, value)
    }
}

impl Write for ClickWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.output {
            WriterOutput::Stdout(ref mut stdout) => stdout.write(buf),
            WriterOutput::Buffer(ref mut buffer) => buffer.write(buf),
            WriterOutput::File(ref mut file) => file.write(buf),
            WriterOutput::Pipe(ref mut pipe_proc) => pipe_proc.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        match self.output {
            WriterOutput::Stdout(ref mut stdout) => stdout.flush(),
            WriterOutput::Buffer(ref mut buffer) => buffer.flush(),
            WriterOutput::File(ref mut file) => file.flush(),
            WriterOutput::Pipe(ref mut pipe_proc) => pipe_proc.flush(),
        }
    }
}

pub struct PrettyColorFormatter<'a> {
    pretty: PrettyFormatter<'a>,
    invalue: bool,
    iskey: bool,
}

impl<'a> PrettyColorFormatter<'a> {
    pub fn new() -> PrettyColorFormatter<'a> {
        PrettyColorFormatter {
            pretty: PrettyFormatter::new(),
            invalue: false,
            iskey: false,
        }
    }
}

impl<'a> Formatter for PrettyColorFormatter<'a> {
    fn write_null<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_null(writer)
    }

    fn write_bool<W: ?Sized>(&mut self, writer: &mut W, value: bool) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_bool(writer, value)
    }

    fn write_i8<W: ?Sized>(&mut self, writer: &mut W, value: i8) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_i8(writer, value)
    }

    fn write_i16<W: ?Sized>(&mut self, writer: &mut W, value: i16) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_i16(writer, value)
    }

    fn write_i32<W: ?Sized>(&mut self, writer: &mut W, value: i32) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_i32(writer, value)
    }

    fn write_i64<W: ?Sized>(&mut self, writer: &mut W, value: i64) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_i64(writer, value)
    }

    fn write_u8<W: ?Sized>(&mut self, writer: &mut W, value: u8) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_u8(writer, value)
    }

    fn write_u16<W: ?Sized>(&mut self, writer: &mut W, value: u16) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_u16(writer, value)
    }

    fn write_u32<W: ?Sized>(&mut self, writer: &mut W, value: u32) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_u32(writer, value)
    }

    fn write_u64<W: ?Sized>(&mut self, writer: &mut W, value: u64) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_u64(writer, value)
    }

    fn write_f32<W: ?Sized>(&mut self, writer: &mut W, value: f32) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_f32(writer, value)
    }

    fn write_f64<W: ?Sized>(&mut self, writer: &mut W, value: f64) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_f64(writer, value)
    }

    fn begin_string<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        if self.invalue && !self.iskey {
            write!(writer, "{}", Green.prefix()).unwrap_or(());
        }
        self.pretty.begin_string(writer)
    }

    fn end_string<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let r = self.pretty.end_string(writer);
        if self.invalue && !self.iskey {
            write!(writer, "{}", Green.suffix()).unwrap_or(());
        }
        r
    }

    fn write_string_fragment<W: ?Sized>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_string_fragment(writer, fragment)
    }

    fn write_char_escape<W: ?Sized>(
        &mut self,
        writer: &mut W,
        char_escape: CharEscape,
    ) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.write_char_escape(writer, char_escape)
    }

    fn begin_array<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.begin_array(writer)
    }

    fn end_array<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.end_array(writer)
    }

    fn begin_array_value<W: ?Sized>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.end_array_value(writer)
    }

    fn begin_object<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.begin_object(writer)
    }

    fn end_object<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.pretty.end_object(writer)
    }

    fn begin_object_key<W: ?Sized>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: Write,
    {
        self.iskey = true;
        let r = self.pretty.begin_object_key(writer, first);
        write!(writer, "{}", Blue.bold().prefix()).unwrap_or(());
        r
    }

    fn end_object_key<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let r = self.pretty.end_object_key(writer);
        self.iskey = false;
        write!(writer, "{}", Blue.bold().suffix()).unwrap_or(());
        r
    }

    fn begin_object_value<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let r = self.pretty.begin_object_value(writer);
        self.invalue = true;
        r
    }

    fn end_object_value<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.invalue = false;
        self.pretty.end_object_value(writer)
    }
}
