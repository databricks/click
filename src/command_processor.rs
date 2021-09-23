use crate::cmd::Cmd;
use crate::completer::ClickHelper;
use crate::error::KubeError;
use crate::kobj::KObj;
use crate::output::ClickWriter;
use crate::parser::{try_parse_csl, try_parse_range, Parser};

use rustyline::config as rustyconfig;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use crate::env::Env;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Things the can come after a | or > char in input
#[derive(Debug, PartialEq)]
enum RightExpr<'a> {
    None,
    /// pipe to command with args
    Pipe(&'a str),
    /// redir to file
    Redir(&'a str),
    /// redir and append to
    Append(&'a str),
}

fn build_parser_expr(line: &str, range: Range<usize>) -> Result<(&str, RightExpr<'_>), KubeError> {
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
                    RightExpr::Redir(rest[sepcnt..].trim())
                } else {
                    RightExpr::Append(rest[sepcnt..].trim())
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

pub fn alias_expand_line(env: &Env, line: &str) -> String {
    let expa = env.try_expand_alias(line, None);
    let mut alias_stack = vec![expa];
    #[allow(clippy::while_let_loop)] // needed due to borrow restrictions
    loop {
        let expa = match alias_stack.last().unwrap().expansion {
            Some(prev) => {
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
fn get_editor(config: rustyconfig::Config, hist_path: &Path) -> Editor<ClickHelper> {
    let mut rl = Editor::<ClickHelper>::with_config(config);
    rl.set_helper(Some(ClickHelper::new(
        CommandProcessor::get_command_vec(),
        vec![
            "completion",
            "edit_mode",
            "shell",
            "pipes",
            "redirection",
            "ranges",
        ],
    )));
    rl.load_history(hist_path).unwrap_or_default();
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
        let commands: Vec<Box<dyn Cmd>> = vec![
            Box::new(crate::cmd::Services::new()),
            Box::new(crate::cmd::ReplicaSets::new()),
            Box::new(crate::cmd::ConfigMaps::new()),
            Box::new(crate::cmd::Secrets::new()),
            Box::new(crate::cmd::Jobs::new()),
            Box::new(crate::command::alias::Alias::new()),
            Box::new(crate::command::alias::Unalias::new()),
            Box::new(crate::command::click::Clear::new()),
            Box::new(crate::command::click::Context::new()),
            Box::new(crate::command::click::Contexts::new()),
            Box::new(crate::command::click::EnvCmd::new()),
            Box::new(crate::command::click::Quit::new()),
            Box::new(crate::command::click::Range::new()),
            Box::new(crate::command::click::SetCmd::new()),
            Box::new(crate::command::click::UtcCmd::new()),
            Box::new(crate::command::delete::Delete::new()),
            Box::new(crate::command::deployments::Deployments::new()),
            Box::new(crate::command::describe::Describe::new()),
            Box::new(crate::command::events::Events::new()),
            Box::new(crate::command::exec::Exec::new()),
            Box::new(crate::command::logs::Logs::new()),
            Box::new(crate::command::namespaces::Namespace::new()),
            Box::new(crate::command::namespaces::Namespaces::new()),
            Box::new(crate::command::nodes::Nodes::new()),
            Box::new(crate::command::pods::Containers::new()),
            Box::new(crate::command::pods::Pods::new()),
            Box::new(crate::command::portforwards::PortForward::new()),
            Box::new(crate::command::portforwards::PortForwards::new()),
            Box::new(crate::command::volumes::PersistentVolumes::new()),
            Box::new(crate::command::statefulsets::StatefulSets::new()),
        ];
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
                    clickwriteln!(writer, "Error reading input: {}", e);
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
                            println!("{}", e);
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
                        // Switch to this when map_while is stable
                        // let objs: Vec<KObj> =
                        //     range.map_while(|i| env.item_at(*i).clone()).collect();
                        let mut objs = vec![];
                        for i in range {
                            match env.item_at(i) {
                                Some(obj) => objs.push(obj.clone()),
                                None => break,
                            }
                        }
                        if objs.is_empty() {
                            env.clear_current();
                        } else {
                            env.set_range(objs);
                        }
                    } else if let Some(range) = try_parse_csl(left) {
                        // parse whole thing before sep since we might type "1, 2, 3" with spaces
                        let objs: Vec<KObj> =
                            range.filter_map(|i| env.item_at(i).cloned()).collect();
                        if objs.is_empty() {
                            env.clear_current();
                        } else {
                            env.set_range(objs);
                        }
                    } else if let Some(cmd) = self.commands.iter().find(|&c| c.is(cmdstr)) {
                        // found a matching command
                        cmd.exec(env, &mut parts, &mut writer);
                    } else if cmdstr == "help" {
                        self.show_help(&mut parts, &mut writer);
                    } else {
                        clickwriteln!(writer, "Unknown command");
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
                        clickwriteln!(writer, "{}", SHELLP);
                    }
                    "completion" => {
                        clickwriteln!(writer, "{}", COMPLETIONHELP);
                    }
                    "edit_mode" => {
                        clickwriteln!(writer, "{}", EDITMODEHELP);
                    }
                    "ranges" => {
                        clickwriteln!(writer, "{}", RANGEHELP);
                    }
                    _ => {
                        if let Some(alias) = self.env.get_alias(hcmd) {
                            clickwriteln!(writer, "{} is an alias for '{}'", hcmd, alias.expanded);
                        } else {
                            clickwriteln!(writer, "I don't know anything about {}, sorry", hcmd);
                        }
                    }
                }
            }
        } else {
            clickwriteln!(
                writer,
                "Available commands (type 'help [COMMAND]' for details):"
            );
            let spacer = "                  ";
            for c in self.commands.iter() {
                clickwriteln!(
                    writer,
                    "  {}{}{}",
                    c.get_name(),
                    &spacer[0..(20 - c.get_name().len())],
                    c.about()
                );
            }
            clickwriteln!(
                writer,
                "\nOther help topics (type 'help [TOPIC]' for details)"
            );
            clickwriteln!(
                writer,
                "  completion          Available completion_type values \
                 for the 'set' command, and what they mean"
            );
            clickwriteln!(
                writer,
                "  edit_mode           Available edit_mode values for \
                 the 'set' command, and what they mean"
            );
            clickwriteln!(
                writer,
                "  ranges              Selecting and operating on multiple \
                 objects at once"
            );
            clickwriteln!(
                writer,
                "  shell               Redirecting and piping click \
                 output to shell commands"
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

// TODO: Something better than raw escapes maybe?
static RANGEHELP: &str = "\u{001b}[33;1mRANGES\u{001b}[0m
Ranges are used to operate on more than one object at a time.

\u{001b}[33;1mSELECTING A RANGE\u{001b}[0m
You can select a range after running a command like 'pods' or 'services' that return a list
of objects. There are two formats to select a range: range syntax, or a comma separated list
of numbers. Once specified the prompt will indicate how many objects you have selected.

\u{001b}[32mRange Syntax\u{001b}[0m
The rust range syntax is:

start..end   (exclusive end)
start..=end  (inclusive end)
..end        (start at 0, exclusive end)
..=end       (start at 0, inclusive end)
start..      (start to end of list)
..           (the whole list)

\u{001b}[33mExamples:\u{001b}[0m
1..3    # select items 1 and 2
1..=3   # select items 1, 2 and 3
..4     # select items 0, 1, 2, and 3
3..     # select items 3 and higher
..      # select everything in the list

\u{001b}[32mComma Separated List\u{001b}[0m
You can specify a list of items to select like: '1,3,12' to select items 1, 3, and 12.
Note that if you want to include spaces, you'll need to quote the string like:
\"1, 3,  12\"

\u{001b}[33;1mPRINTING THE CURRENT RANGE\u{001b}[0m
The 'range' command will print out a table of objects in the current range. This is useful
to verify your commands will operate on the objects you expect.

\u{001b}[33;1mCOMMANDS ON RANGES\u{001b}[0m
Once you have selected a range, you can run any of the following commands which will operate on each
item in the range in turn:

containers, describe, delete, events, exec, logs

\u{001b}[33;1mRANGE SEPARATOR\u{001b}[0m
When printing output for the above commands over a range, Click will print a header for each item.
The format is defined by the range separator. You can view the current separator with the 'env'
command, and you can set it via 'set range_separator \"my separator\"'. This string can be templated
as follows:
{name}      - replaced with the name of the object
{namespace} - replaced with the namespace of the object

For example:
> set range_separator \"=== {name}:{namespace} ===\"
means commands on ranges print the name and namespace of each object along with the '='s characters.

\u{001b}[33;1mLOGS FOR A RANGE\u{001b}[0m
When getting logs for a range you may wish to write each pod's logs to its own file. To do so, use
the '-o' option with logs. The argument you pass to -o can be templated as follows:
{name}      - replaced with the name of the object
{namespace} - replaced with the namespace of the object
{time}      - replaced with the rfc3339 date and time for when the command was run

For example, if a range was selected the following command would get the last 100 lines of logs for
each pod in the range, and write it to /tmp/podname-rfc3339date.log:
[context][namespace][5 Pods selected] > logs -t 100 -o \"/tmp/{name}-{time}.log\"
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{get_test_config, Alias, ClickConfig};
    use crate::env::ObjectSelection;
    use crate::kobj::{KObj, ObjType};

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
            clickwriteln!(writer, "HELP");
        }

        fn about(&self) -> &'static str {
            "This is the about"
        }

        fn try_complete(&self, _index: usize, _prefix: &str, _env: &Env) -> Vec<RustlinePair> {
            Vec::new()
        }

        fn try_completed_named(
            &self,
            _index: usize,
            _opt: &str,
            _prefix: &str,
            _env: &Env,
        ) -> Vec<RustlinePair> {
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

    fn make_node(name: &str) -> crate::kube::Node {
        crate::kube::Node {
            metadata: crate::kube::Metadata::with_name(name),
            spec: crate::kube::NodeSpec {
                unschedulable: Some(false),
            },
            status: crate::kube::NodeStatus {
                conditions: Vec::new(),
            },
        }
    }

    fn make_node_kobj(name: &str) -> KObj {
        KObj {
            name: name.to_string(),
            namespace: None,
            typ: ObjType::Node,
        }
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
  ranges              Selecting and operating on multiple objects at once
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
        let node = make_node("ns1");
        let nodelist = crate::kube::NodeList { items: vec![node] };
        env.set_last_objs(nodelist);
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
    fn range_selection() {
        let commands: Vec<Box<dyn Cmd>> = Vec::new();
        let mut env = Env::new(
            get_test_config(),
            ClickConfig::default(),
            PathBuf::from("/tmp/click.conf"),
        );
        let node1 = make_node("ns1");
        let node2 = make_node("ns2");
        let node3 = make_node("ns3");
        let nodelist = crate::kube::NodeList {
            items: vec![node1, node2, node3],
        };
        env.set_last_objs(nodelist);
        let mut p = CommandProcessor::new_with_commands(
            env,
            PathBuf::from("/tmp/click.test.hist"),
            commands,
        );

        p.process_line("0..=1", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Range(vec![make_node_kobj("ns1"), make_node_kobj("ns2"),])
        );

        p.process_line("0..", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Range(vec![
                make_node_kobj("ns1"),
                make_node_kobj("ns2"),
                make_node_kobj("ns3"),
            ])
        );

        p.process_line("0..1", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Range(vec![make_node_kobj("ns1")])
        );

        p.process_line("8..10", ClickWriter::new());
        assert_eq!(p.env.current_selection(), &ObjectSelection::None);

        p.process_line("0,2", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Range(vec![make_node_kobj("ns1"), make_node_kobj("ns3")])
        );

        p.process_line("2,1", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Range(vec![make_node_kobj("ns3"), make_node_kobj("ns2")])
        );

        p.process_line("9, 2, 1, 6", ClickWriter::new());
        assert_eq!(
            p.env.current_selection(),
            &ObjectSelection::Range(vec![make_node_kobj("ns3"), make_node_kobj("ns2")])
        );

        p.process_line("8,10", ClickWriter::new());
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
    fn unexpected_chars() {
        let p = parse_line("test || this");
        assert!(p.is_err());
        assert_eq!(
            p.err().unwrap().to_string(),
            "Parse Error: Parse error at 5: unexpected ||"
        );

        let p = parse_line("test >>> this");
        assert!(p.is_err());
        assert_eq!(
            p.err().unwrap().to_string(),
            "Parse Error: Parse error at 5: unexpected >>"
        );

        let p = parse_line("test >>>> this");
        assert!(p.is_err());
        assert_eq!(
            p.err().unwrap().to_string(),
            "Parse Error: Parse error at 5: unexpected >>"
        );

        let p = build_parser_expr("a * b", std::ops::Range { start: 2, end: 5 });
        assert!(p.is_err());
        assert_eq!(
            p.err().unwrap().to_string(),
            "Parse Error: Parse error at 2: unexpected separator"
        );
    }

    #[test]
    fn build_parser_exp() {
        let p = build_parser_expr("a | b", std::ops::Range { start: 2, end: 5 });
        assert!(p.is_ok());
        let r = p.unwrap();
        assert_eq!(r.0, "a ");
        assert_eq!(r.1, RightExpr::Pipe(" b"));

        let p = build_parser_expr("a > b", std::ops::Range { start: 2, end: 5 });
        assert!(p.is_ok());
        let r = p.unwrap();
        assert_eq!(r.0, "a ");
        assert_eq!(r.1, RightExpr::Redir("b"));

        let p = build_parser_expr("a >> b", std::ops::Range { start: 2, end: 6 });
        assert!(p.is_ok());
        let r = p.unwrap();
        assert_eq!(r.0, "a ");
        assert_eq!(r.1, RightExpr::Append("b"));
    }

    #[test]
    fn hist_ignore() {
        let mut p = get_processor();
        let buf = vec![];
        let writer = ClickWriter::with_buffer(buf, false);
        p.process_line(" testcmd", writer);
        assert_eq!(p.rl.history().len(), 0);
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
