use cmd::Cmd;
use completer::ClickHelper;
use error::KubeError;
use output::ClickWriter;
use parser::Parser;

use rustyline::config as rustyconfig;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use Env;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;

/// Things the can come after a | or > char in input
enum RightExpr<'a> {
    None,
    /// pipe to command with args
    Pipe(&'a str),
    /// redir to file
    Redir(&'a str),
    /// redir and append to
    Append(&'a str),
}

fn build_parser_expr<'a>(
    line: &'a str,
    range: Range<usize>,
) -> Result<(&'a str, RightExpr<'a>), KubeError> {
    let (click_cmd, rest) = line.split_at(range.start);

    let rbytes = rest.as_bytes();
    let sep = rbytes[0];
    let mut sepcnt = 0;

    while rbytes[sepcnt] == sep {
        sepcnt += 1;
    }

    if sep == b'|' && sepcnt > 1 {
        Err(KubeError::ParseErr(format!(
            "Parse error at {}: unexpected ||",
            range.start
        )))
    } else if sep == b'>' && sepcnt > 2 {
        Err(KubeError::ParseErr(format!(
            "Parse error at {}: unexpected >>",
            range.start
        )))
    } else {
        let right = match sep {
            b'|' => RightExpr::Pipe(&rest[sepcnt..]),
            b'>' => {
                if sepcnt == 1 {
                    RightExpr::Redir(&rest[sepcnt..].trim())
                } else {
                    RightExpr::Append(&rest[sepcnt..].trim())
                }
            }
            _ => {
                return Err(KubeError::ParseErr(format!(
                    "Parse error at {}: unexpected separator",
                    range.start
                )))
            }
        };
        Ok((click_cmd, right))
    }
}

fn alias_expand_line(env: &Env, line: &str) -> String {
    let expa = env.try_expand_alias(line, None);
    let mut alias_stack = vec![expa];
    #[allow(clippy::while_let_loop)] // needed due to borrow restrictions
    loop {
        let expa = match alias_stack.last().unwrap().expansion {
            Some(ref prev) => {
                // previous thing expanded an alias, so try and expand that too
                env.try_expand_alias(prev.expanded.as_str(), Some(prev.alias.as_str()))
            }
            None => break,
        };
        alias_stack.push(expa);
    }
    // At this point, all the "real" stuff is in the chain of "rest" memebers of the
    // alias_stack, let's gather them up
    let rests: Vec<&str> = alias_stack.iter().rev().map(|ea| ea.rest).collect();
    rests.concat()
}

fn parse_line(line: &str) -> Result<(&str, RightExpr), KubeError> {
    let parser = Parser::new(line);
    for (range, sep, _) in parser {
        match sep {
            '|' | '>' => return build_parser_expr(line, range),
            _ => {}
        }
    }
    Ok((line, RightExpr::None))
}

// see comment on ClickCompleter::new for why a raw pointer is needed
fn get_editor<'a>(
    config: rustyconfig::Config,
    raw_env: *const Env,
    hist_path: &PathBuf,
    commands: Vec<Box<dyn Cmd>>,
) -> Editor<ClickHelper<'a>> {
    let mut rl = Editor::<ClickHelper>::with_config(config);
    rl.load_history(hist_path.as_path()).unwrap_or_default();
    rl.set_helper(Some(ClickHelper::new(commands, raw_env)));
    rl
}

pub struct CommandProcessor<'a> {
    env: Env,
    rl: Editor<ClickHelper<'a>>,
    hist_path: PathBuf,
    commands: Vec<Box<dyn Cmd>>,
}

impl<'a> CommandProcessor<'a> {
    pub fn new(env: Env, hist_path: PathBuf) -> CommandProcessor<'a> {
        let commands = CommandProcessor::get_command_vec();
        let rl = get_editor(
            env.get_rustyline_conf(),
            &env,
            &hist_path,
            CommandProcessor::get_command_vec(),
        );
        CommandProcessor {
            env,
            rl,
            hist_path,
            commands,
        }
    }

    #[cfg(test)]
    fn new_with_commands(
        env: Env,
        hist_path: PathBuf,
        commands: Vec<Box<dyn Cmd>>,
    ) -> CommandProcessor<'a> {
        let rl = get_editor(
            env.get_rustyline_conf(),
            &env,
            &hist_path,
            Vec::new(),
        );
        CommandProcessor {
            env,
            rl,
            hist_path,
            commands,
        }
    }

    fn get_command_vec() -> Vec<Box<dyn Cmd>> {
        let mut commands: Vec<Box<dyn Cmd>> = Vec::new();
        commands.push(Box::new(::cmd::Quit::new()));
        commands.push(Box::new(::cmd::Context::new()));
        commands.push(Box::new(::cmd::Contexts::new()));
        commands.push(Box::new(::cmd::Pods::new()));
        commands.push(Box::new(::cmd::Nodes::new()));
        commands.push(Box::new(::cmd::Deployments::new()));
        commands.push(Box::new(::cmd::Services::new()));
        commands.push(Box::new(::cmd::ReplicaSets::new()));
        commands.push(Box::new(::cmd::StatefulSets::new()));
        commands.push(Box::new(::cmd::ConfigMaps::new()));
        commands.push(Box::new(::cmd::Namespace::new()));
        commands.push(Box::new(::cmd::Logs::new()));
        commands.push(Box::new(::cmd::Describe::new()));
        commands.push(Box::new(::cmd::Exec::new()));
        commands.push(Box::new(::cmd::Containers::new()));
        commands.push(Box::new(::cmd::Events::new()));
        commands.push(Box::new(::cmd::Clear::new()));
        commands.push(Box::new(::cmd::EnvCmd::new()));
        commands.push(Box::new(::cmd::SetCmd::new()));
        commands.push(Box::new(::cmd::Delete::new()));
        commands.push(Box::new(::cmd::UtcCmd::new()));
        commands.push(Box::new(::cmd::Namespaces::new()));
        commands.push(Box::new(::cmd::Secrets::new()));
        commands.push(Box::new(::cmd::PortForward::new()));
        commands.push(Box::new(::cmd::PortForwards::new()));
        commands.push(Box::new(::cmd::Jobs::new()));
        commands.push(Box::new(::cmd::Alias::new()));
        commands.push(Box::new(::cmd::Unalias::new()));
        commands
    }

    pub fn run_repl(&'a mut self) {
        while !self.env.quit {
            let writer = ClickWriter::new();
            if self.env.need_new_editor {
                self.rl = get_editor(
                    self.env.get_rustyline_conf(),
                    &self.env,
                    &self.hist_path,
                    CommandProcessor::get_command_vec(),
                );
                self.env.need_new_editor = false;
            }
            let readline = self.rl.readline(self.env.prompt.as_str());
            match readline {
                Ok(line) => {
                    self.process_line(line.as_str(), writer);
                }
                Err(ReadlineError::Interrupted) => {} // don't exit on Ctrl-C
                Err(ReadlineError::Eof) => {
                    // Ctrl-D
                    break;
                }
                Err(e) => {
                    println!("Error reading input: {}", e);
                    break;
                }
            }
        }
        self.env.save_click_config();
        if let Err(e) = self.rl.save_history(self.hist_path.as_path()) {
            println!("Couldn't save command history: {}", e);
        }
        self.env.stop_all_forwards();
    }

    pub fn process_line<W: Write>(&mut self, line: &str, mut writer: ClickWriter<W>) {
        if line.is_empty() {
            return;
        }
        let mut first_non_whitespace = 0;
        for c in line.chars() {
            if !c.is_whitespace() {
                break;
            }
            first_non_whitespace += 1;
        }
        let lstr = if first_non_whitespace == 0 {
            // bash semantics: don't add to history if start with space
            self.rl.add_history_entry(line);
            line
        } else {
            &line[first_non_whitespace..]
        };
        let expanded_line = alias_expand_line(&self.env, lstr);
        match parse_line(&expanded_line) {
            Ok((left, right)) => {
                // set up output
                let writer =
                    match right {
                        RightExpr::None => writer, // do nothing
                        RightExpr::Pipe(cmd) => {
                            match ClickWriter::with_pipe(writer.writer, cmd) {
                                Ok(w) => w,
                                Err(e) => {
                                    clickwrite!(writer, "{}", e.description());
                                    return;
                                }
                            }
                        }
                        RightExpr::Redir(filename) => match File::create(filename) {
                            Ok(out_file) => {
                                ClickWriter::with_writer(out_file, false)
                            }
                            Err(ref e) => {
                                clickwrite!(writer, "Can't open output file: {}", e);
                                return;
                            }
                        },
                        RightExpr::Append(filename) => {
                            match OpenOptions::new().append(true).create(true).open(filename) {
                                Ok(out_file) => {
                                    ClickWriter::with_writer(out_file, false)
                                }
                                Err(ref e) => {
                                    clickwrite!(writer, "Can't open output file: {}", e);
                                    return;
                                }
                            }
                        }
                    };

                let parts_vec: Vec<String> = Parser::new(left).map(|x| x.2).collect();
                let mut parts = parts_vec.iter().map(|s| &**s);
                if let Some(cmdstr) = parts.next() {
                    // There was something typed
                    if let Ok(num) = (cmdstr as &str).parse::<usize>() {
                        self.env.set_current(num);
                    } else if let Some(cmd) = self.commands.iter().find(|&c| c.is(cmdstr)) {
                        // found a matching command
                        cmd.exec(&mut self.env, &mut parts, &mut writer);
                    } else if cmdstr == "help" {
                        // help isn't a command as it needs access to the commands vec
                        if let Some(hcmd) = parts.next() {
                            if let Some(cmd) = self.commands.iter().find(|&c| c.is(hcmd)) {
                                cmd.write_help(&mut writer);
                            } else {
                                match hcmd {
                                    // match for meta topics
                                    "pipes" | "redirection" | "shell" => {
                                        clickwrite!(writer, "{}\n", SHELLP);
                                    }
                                    "completion" => {
                                        clickwrite!(writer, "{}\n", COMPLETIONHELP);
                                    }
                                    "edit_mode" => {
                                        clickwrite!(writer, "{}\n", EDITMODEHELP);
                                    }
                                    _ => {
                                        clickwrite!(
                                            writer,
                                            "I don't know anything about {}, sorry\n",
                                            hcmd
                                        );
                                    }
                                }
                            }
                        } else {
                            clickwrite!(
                                writer,
                                "Available commands (type 'help [COMMAND]' for details):\n"
                            );
                            let spacer = "                  ";
                            for c in self.commands.iter() {
                                clickwrite!(
                                    writer,
                                    "  {}{}{}\n",
                                    c.get_name(),
                                    &spacer[0..(20 - c.get_name().len())],
                                    c.about()
                                );
                            }
                            clickwrite!(
                                writer,
                                "\nOther help topics (type 'help [TOPIC]' for details)\n"
                            );
                            clickwrite!(
                                writer,
                                "  completion          Available completion_type values \
                                 for the 'set' command, and what they mean\n"
                            );
                            clickwrite!(
                                writer,
                                "  edit_mode           Available edit_mode values for \
                                 the 'set' command, and what they mean\n"
                            );
                            clickwrite!(
                                writer,
                                "  shell               Redirecting and piping click \
                                 output to shell commands\n"
                            );
                        }
                    } else {
                        clickwrite!(writer, "Unknown command\n");
                    }
                }

                // reset output
                writer.finish_output();
            }
            Err(err) => {
                println!("{}", err);
            }
        }
    }
}

static SHELLP: &str = "Shell syntax can be used to redirect or pipe the output of click \
commands to files or other commands (like grep).\n
Examples:\n\
 # grep logs for ERROR:\n\
 logs my-cont | grep ERROR\n\n\
 # pass output of describe -j to jq, then grep for foo \n\
 describe -j | jq . | grep foo\n\n\
 # Save logs to logs.txt:\n\
 logs my-cont > /tmp/logs.txt\n\n\
 # Append log lines that contain \"foo bar\" to logs.txt\n\
 logs the-cont | grep \"foo bar\" >> /tmp/logs.txt";

static COMPLETIONHELP: &str = "There are two completion types: list or circular.
- 'list' will complete the next full match (like in Vim by default) (do: 'set completion list)
- circular will complete until the longest match. If there is more than one match, \
it will list all matches (like in Bash/Readline). (do: set completion circular)";

static EDITMODEHELP: &str = "There are two edit modes: vi or emacs.
This controls the style of editing and the standard keymaps to the mode used by the \
associated editor.
- 'vi' Hit ESC while editing to edit the line using common vi keybindings (do: 'set edit_mode vi')
- 'emacs' Use standard readline/bash/emacs keybindings (do: 'set edit_mode emacs')";

#[cfg(test)]
mod tests {
    use super::*;
    use config::{get_test_config, ClickConfig};
    use rustyline::completion::Pair as RustlinePair;

    use std::path::PathBuf;

    struct TestCmd;
    impl Cmd for TestCmd {
        fn exec<W: Write>(
            &self,
            _env: &mut Env,
            _args: &mut dyn Iterator<Item = &str>,
            _writer: &mut ClickWriter<W>,
        ) -> bool {
            println!("Called");
            true
        }

        fn is(&self, _l: &str) -> bool {
            false
        }

        fn get_name(&self) -> &'static str {
            "testcmd"
        }

        fn write_help<W: Write>(&self, writer: &mut ClickWriter<W>) {
            clickwrite!(writer, "HELP\n");
        }

        fn about(&self) -> &'static str {
            "This is the about"
        }

        fn try_complete(&self, _index: usize, _prefix: &str, _env: &Env) -> Vec<RustlinePair> {
            Vec::new()
        }

        fn complete_option(&self, _prefix: &str) -> Vec<RustlinePair> {
            Vec::new()
        }
    }

    #[test]
    fn test_help() {
        let mut commands: Vec<Box<dyn Cmd>> = Vec::new();
        commands.push(Box::new(TestCmd));
        let mut p = CommandProcessor::new_with_commands(
            Env::new(
                get_test_config(),
                ClickConfig::default(),
                PathBuf::from("/tmp/click.conf"),
            ),
            PathBuf::from("/tmp/click.test.hist"),
            commands,
        );
        let writer = ClickWriter::new();
        p.process_line("help testcmd", writer);
    }
}
