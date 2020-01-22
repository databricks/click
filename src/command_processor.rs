use cmd::Cmd;
use completer::ClickHelper;
use error::KubeError;
use output::ClickWriter;
use parser::{try_parse_range, Parser};

use rustyline::config as rustyconfig;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use env::Env;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;
use std::rc::Rc;

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
fn get_editor(config: rustyconfig::Config, hist_path: &PathBuf) -> Editor<ClickHelper> {
    let mut rl = Editor::<ClickHelper>::with_config(config);
    rl.set_helper(Some(ClickHelper::new(
        CommandProcessor::get_command_vec(),
        vec!["completion", "edit_mode", "shell", "pipes", "redirection", "ranges"],
    )));
    rl.load_history(hist_path.as_path()).unwrap_or_default();
    rl
}

pub struct CommandProcessor {
    env: Rc<Env>,
    rl: Editor<ClickHelper>,
    hist_path: PathBuf,
    commands: Vec<Box<dyn Cmd>>,
}

impl CommandProcessor {
    pub fn new(env: Env, hist_path: PathBuf) -> CommandProcessor {
        let commands = CommandProcessor::get_command_vec();
        let env = Rc::new(env);
        let rl = get_editor(env.get_rustyline_conf(), &hist_path);
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
    ) -> CommandProcessor {
        let env = Rc::new(env);
        let rl = get_editor(env.get_rustyline_conf(), &hist_path);
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
        commands.push(Box::new(::cmd::Range::new()));
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

    pub fn run_repl(&mut self) {
        while !self.env.quit {
            let mut writer = ClickWriter::new();
            if self.env.need_new_editor {
                self.rl = get_editor(self.env.get_rustyline_conf(), &self.hist_path);
                Rc::get_mut(&mut self.env).unwrap().need_new_editor = false;
            }

            // we set and unset the pointer to the env in the helper here so the get_mut below works
            let helper_env = Some(self.env.clone());
            if let Some(h) = self.rl.helper_mut() {
                h.set_env(helper_env)
            }
            let readline = self.rl.readline(self.env.prompt.as_str());
            if let Some(h) = self.rl.helper_mut() {
                h.set_env(None)
            }
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
                    clickwrite!(writer, "Error reading input: {}\n", e);
                    break;
                }
            }
        }
        let env = Rc::get_mut(&mut self.env).unwrap();
        env.save_click_config();
        if let Err(e) = self.rl.save_history(self.hist_path.as_path()) {
            println!("Couldn't save command history: {}", e);
        }
        env.stop_all_forwards();
    }

    /// Process the line.  Returns the result of finish_output on the writer
    pub fn process_line(&mut self, line: &str, mut writer: ClickWriter) -> Option<Vec<u8>> {
        if line.is_empty() {
            return writer.finish_output();
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
                match right {
                    RightExpr::None => {} // do nothing
                    RightExpr::Pipe(cmd) => {
                        if let Err(e) = writer.setup_pipe(cmd) {
                            println!("{}", e.description());
                            return writer.finish_output();
                        }
                    }
                    RightExpr::Redir(filename) => match File::create(filename) {
                        Ok(out_file) => {
                            writer.set_output_file(out_file);
                        }
                        Err(ref e) => {
                            println!("Can't open output file: {}", e);
                            return writer.finish_output();
                        }
                    },
                    RightExpr::Append(filename) => {
                        match OpenOptions::new().append(true).create(true).open(filename) {
                            Ok(out_file) => {
                                writer.set_output_file(out_file);
                            }
                            Err(ref e) => {
                                println!("Can't open output file: {}", e);
                                return writer.finish_output();
                            }
                        }
                    }
                }

                let parts_vec: Vec<String> = Parser::new(left).map(|x| x.2).collect();
                let mut parts = parts_vec.iter().map(|s| &**s);
                let env = Rc::get_mut(&mut self.env).unwrap();
                if let Some(cmdstr) = parts.next() {
                    // There was something typed
                    if let Ok(num) = (cmdstr as &str).parse::<usize>() {
                        env.set_current(num);
                    } else if let Some(range) = try_parse_range(cmdstr) {
                        let mut objs = vec![];
                        for i in range {
                            match env.item_at(i) {
                                Some(obj) => objs.push(obj),
                                None => break,
                            }
                        }
                        env.set_range(objs);
                    } else if let Some(cmd) = self.commands.iter().find(|&c| c.is(cmdstr)) {
                        // found a matching command
                        cmd.exec(env, &mut parts, &mut writer);
                    } else if cmdstr == "help" {
                        self.show_help(&mut parts, &mut writer);
                    } else {
                        clickwrite!(writer, "Unknown command\n");
                    }
                }

                // reset output
                writer.finish_output()
            }
            Err(err) => {
                println!("{}", err);
                None
            }
        }
    }

    fn show_help(&mut self, parts: &mut dyn Iterator<Item = &str>, writer: &mut ClickWriter) {
        // help isn't a command as it needs access to the commands vec
        if let Some(hcmd) = parts.next() {
            if let Some(cmd) = self.commands.iter().find(|&c| c.is(hcmd)) {
                cmd.write_help(writer);
            } else {
                match hcmd {
                    // match for meta topics (add new topics to the ClickHelper above!)
                    "pipes" | "redirection" | "shell" => {
                        clickwrite!(writer, "{}\n", SHELLP);
                    }
                    "completion" => {
                        clickwrite!(writer, "{}\n", COMPLETIONHELP);
                    }
                    "edit_mode" => {
                        clickwrite!(writer, "{}\n", EDITMODEHELP);
                    }
                    "ranges" => {
                        clickwrite!(writer, "{}\n", RANGEHELP);
                    }
                    _ => {
                        clickwrite!(writer, "I don't know anything about {}, sorry\n", hcmd);
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
- list: complete the next full match (like in Vim by default) (do: set completion list)
- circular: complete until the longest match. If there is more than one match, \
it will list all matches (like in Bash/Readline). (do: set completion circular)";

static EDITMODEHELP: &str = "There are two edit modes: vi or emacs.
This controls the style of editing and the standard keymaps to the mode used by the \
associated editor.
- 'vi' Hit ESC while editing to edit the line using common vi keybindings (do: 'set edit_mode vi')
- 'emacs' Use standard readline/bash/emacs keybindings (do: 'set edit_mode emacs')";

static RANGEHELP: &str = "Ranges are used to operate on more than one object at a time.


Selecting a range:

You can use the rust range syntax to select a range after running a command that returns a list
of objects like 'pods' or 'services'. The syntax is:

start..end   (exclusive end)
start..=end  (inclusive end)
..end        (start at 0, exclusive end)
..=end       (start at 0, inclusive end)
start..      (start to end of list)
..           (the whole list)

Once specified the prompt will indicate how many objects you have selected.


Commands on ranges:
Once you have selected a range, you can run any of the following commands which will operate on each
item in the range in turn:

containers, describe, delete, events, exec, logs


Range separator:

When printing output for the above commands over a range, Click will print a header for each item.
The format is defined by the range separator. You can view the current separator with the 'env'
command, and you can set it via 'set range_separator \"my separator\"'. This string can be templated
as follows:
{name}      - replaced with the name of the object
{namespace} - replaced with the namespace of the object

For example:
> set range_separator \"=== {name}:{namespace} ===\"
means commands on ranges print the name and namespace of each object along with the '='s characters.


Getting logs for a range:
When getting logs for a range you may wish to write each pod's logs to its own file. To do so, use
the '-o' option with logs. The argument you pass to -o can be templated as follows:
{name}      - replaced with the name of the object
{namespace} - replaced with the namespace of the object
{time}      - replaceed with the rfc3339 date and time for when the command was run

For example, if a range was selected the following command would get the last 100 lines of logs for
each pod in the range, and write it to /tmp/podname-rfc3339date.log:
[context][namespace][5 Pods selected] > logs -t 100 -o \"/tmp/{name}-{time}.log\"
";

#[cfg(test)]
mod tests {
    use super::*;
    use config::{get_test_config, Alias, ClickConfig};
    use env::{LastList, ObjectSelection};
    use kobj::{KObj, ObjType};

    use rustyline::completion::Pair as RustlinePair;

    use std::io::Read;
    use std::path::PathBuf;

    struct TestCmd;
    impl Cmd for TestCmd {
        fn exec(
            &self,
            _env: &mut Env,
            args: &mut dyn Iterator<Item = &str>,
            writer: &mut ClickWriter,
        ) -> bool {
            match args.next() {
                Some(arg) => clickwrite!(writer, "Called with {}", arg),
                None => clickwrite!(writer, "Called with no args"),
            }
            true
        }

        fn is(&self, l: &str) -> bool {
            l == "testcmd"
        }

        fn get_name(&self) -> &'static str {
            "testcmd"
        }

        fn write_help(&self, writer: &mut ClickWriter) {
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

    fn get_processor() -> CommandProcessor {
        let mut commands: Vec<Box<dyn Cmd>> = Vec::new();
        commands.push(Box::new(TestCmd));
        CommandProcessor::new_with_commands(
            Env::new(
                get_test_config(),
                ClickConfig::default(),
                PathBuf::from("/tmp/click.conf"),
            ),
            PathBuf::from("/tmp/click.test.hist"),
            commands,
        )
    }

    #[test]
    fn test_help() {
        let mut p = get_processor();

        let buf = Vec::new();
        let writer = ClickWriter::with_buffer(buf, false);
        let res = p.process_line("help testcmd", writer).unwrap();
        assert_eq!(res, "HELP\n".as_bytes());

        let buf = Vec::new();
        let writer = ClickWriter::with_buffer(buf, false);
        let res = p.process_line("help unknown", writer).unwrap();
        assert_eq!(
            res,
            "I don't know anything about unknown, sorry\n".as_bytes()
        );

        let buf = Vec::new();
        let writer = ClickWriter::with_buffer(buf, false);
        let res = p.process_line("help", writer).unwrap();
        assert_eq!(
            res,
            "Available commands (type 'help [COMMAND]' for details):
  testcmd             This is the about

Other help topics (type 'help [TOPIC]' for details)
  completion          Available completion_type values for the 'set' command, and what they mean
  edit_mode           Available edit_mode values for the 'set' command, and what they mean
  shell               Redirecting and piping click output to shell commands\n"
                .as_bytes()
        );
    }

    #[test]
    fn unknown_command() {
        let mut p = get_processor();
        let buf = Vec::new();
        let writer = ClickWriter::with_buffer(buf, false);
        let res = p.process_line("blah", writer).unwrap();
        assert_eq!(res, "Unknown command\n".as_bytes());
    }

    #[test]
    fn exec() {
        let mut p = get_processor();

        let buf = Vec::new();
        let writer = ClickWriter::with_buffer(buf, false);
        let res = p.process_line("testcmd", writer).unwrap();
        assert_eq!(res, "Called with no args".as_bytes());

        let buf = Vec::new();
        let writer = ClickWriter::with_buffer(buf, false);
        let res = p.process_line("testcmd arg1", writer).unwrap();
        assert_eq!(res, "Called with arg1".as_bytes());
    }

    #[test]
    fn number_selection() {
        let commands: Vec<Box<dyn Cmd>> = Vec::new();
        let mut env = Env::new(
            get_test_config(),
            ClickConfig::default(),
            PathBuf::from("/tmp/click.conf"),
        );
        let node = ::kube::Node {
            metadata: ::kube::Metadata::with_name("ns1"),
            spec: ::kube::NodeSpec {
                unschedulable: Some(false),
            },
            status: ::kube::NodeStatus {
                conditions: Vec::new(),
            },
        };
        let nodelist = ::kube::NodeList { items: vec![node] };
        let ll = LastList::NodeList(nodelist);
        env.set_lastlist(ll);
        let mut p = CommandProcessor::new_with_commands(
            env,
            PathBuf::from("/tmp/click.test.hist"),
            commands,
        );
        p.process_line("0", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Single(KObj {
                name: "ns1".to_string(),
                namespace: None,
                typ: ObjType::Node,
            })
        );

        p.process_line("1", ClickWriter::new());
        assert_eq!(p.env.current_selection(), &ObjectSelection::None);
    }

    #[test]
    fn redir_to_file() {
        let dir = tempdir::TempDir::new("click_test_dir").unwrap();
        let file_path_buf = dir.path().join("foo.txt");
        let ffos = file_path_buf.clone().into_os_string();

        let mut p = get_processor();
        let cmd = format!("testcmd > {}", ffos.to_str().unwrap());
        p.process_line(&cmd, ClickWriter::new());

        let mut file = File::open(file_path_buf).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "Called with no args");

        dir.close().unwrap();
    }

    #[test]
    fn append_to_file() {
        let dir = tempdir::TempDir::new("click_test_dir").unwrap();
        let file_path_buf = dir.path().join("foo_append.txt");
        let ffos = file_path_buf.clone().into_os_string();

        let mut p = get_processor();

        let cmd = format!("testcmd >> {}", ffos.to_str().unwrap());
        p.process_line(&cmd, ClickWriter::new());
        p.process_line(&cmd, ClickWriter::new());

        let mut file = File::open(file_path_buf).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "Called with no argsCalled with no args");

        dir.close().unwrap();
    }

    #[test]
    #[ignore] // we ignore this since we can't guarantee a system has grep
    fn pipeline() {
        let dir = tempdir::TempDir::new("click_test_dir").unwrap();
        let file_path_buf = dir.path().join("foo_pipeline.txt");
        let ffos = file_path_buf.clone().into_os_string();

        let mut p = get_processor();

        let cmd1 = format!("testcmd foo | grep foo >> {}", ffos.to_str().unwrap());
        let cmd2 = format!("testcmd foo | grep bar >> {}", ffos.to_str().unwrap());
        p.process_line(&cmd1, ClickWriter::new());
        p.process_line(&cmd2, ClickWriter::new());

        let mut file = File::open(file_path_buf).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "Called with foo\n");

        dir.close().unwrap();
    }

    #[test]
    fn test_alias_expand_line() {
        let mut cc = ClickConfig::default();
        let pn_alias = Alias {
            alias: "pn".to_string(),
            expanded: "pods --sort node".to_string(),
        };
        let x_alias = Alias {
            alias: "x".to_string(),
            expanded: "xpand".to_string(),
        };
        let x_chain = Alias {
            alias: "y".to_string(),
            expanded: "x".to_string(),
        };

        let x_chain_arg = Alias {
            alias: "z".to_string(),
            expanded: "x arg".to_string(),
        };
        cc.aliases.push(pn_alias);
        cc.aliases.push(x_alias);
        cc.aliases.push(x_chain);
        cc.aliases.push(x_chain_arg);
        let env = Env::new(get_test_config(), cc, PathBuf::from("/tmp/click.config"));

        assert_eq!(alias_expand_line(&env, "pn"), "pods --sort node");

        assert_eq!(alias_expand_line(&env, "x"), "xpand");

        assert_eq!(alias_expand_line(&env, "x args"), "xpand args");

        assert_eq!(alias_expand_line(&env, "not an alias"), "not an alias");

        assert_eq!(alias_expand_line(&env, "x x"), "xpand x");

        assert_eq!(
            alias_expand_line(&env, "pn pn foo"),
            "pods --sort node pn foo"
        );

        assert_eq!(alias_expand_line(&env, "xx x"), "xx x");

        assert_eq!(alias_expand_line(&env, "y"), "xpand");

        assert_eq!(alias_expand_line(&env, "z"), "xpand arg");

        assert_eq!(alias_expand_line(&env, "y arg"), "xpand arg");

        assert_eq!(alias_expand_line(&env, "z outer"), "xpand arg outer");

        assert_eq!(alias_expand_line(&env, "y x"), "xpand x");

        assert_eq!(alias_expand_line(&env, "z x"), "xpand arg x");
    }
}
