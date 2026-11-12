use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser};

use crate::config::constants::{
    APP_ID, CLI_ABOUT, CLI_FORMAT_HELP, CLI_GUI_HELP, CLI_OUTPUT_HELP, CLI_PATHS_HELP,
    CLI_REGISTRY_HELP,
};
use crate::config::localization::resolve_language;
use crate::config::settings::load_settings;
use crate::core::export::export_sessions;
use crate::core::input::load_ini_inputs;
use crate::core::model::ExportFormat;
use crate::core::registry::load_registry_sessions;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(help = CLI_PATHS_HELP)]
    inputs: Vec<PathBuf>,

    #[arg(long, value_enum, help = CLI_FORMAT_HELP)]
    format: Option<ExportFormat>,

    #[arg(long, value_name = "FILE", help = CLI_OUTPUT_HELP)]
    output: Option<PathBuf>,

    #[arg(long, help = CLI_REGISTRY_HELP)]
    registry: bool,

    #[arg(long, help = CLI_GUI_HELP)]
    gui: bool,
}

pub fn run() -> Result<(), String> {
    let command = Cli::command().name(APP_ID).about(CLI_ABOUT);
    let matches = command.get_matches();
    let cli = Cli::from_arg_matches(&matches).map_err(|error| error.to_string())?;

    let (settings, _) = load_settings();
    let language = resolve_language(settings.language);
    let text = crate::config::localization::labels(language);
    if should_open_gui(&cli) {
        return crate::ui::run().map_err(|error| format!("{}\n{error}", text.open_gui_failed));
    }

    if cli.inputs.is_empty() && !cli.registry {
        return Err(text.no_input.to_owned());
    }
    let mut report = load_ini_inputs(&cli.inputs);
    if cli.registry {
        let registry_report = load_registry_sessions().map_err(|_| {
            if cfg!(windows) {
                text.registry_read_failed.to_owned()
            } else {
                text.unsupported_platform.to_owned()
            }
        })?;
        report.append(registry_report);
    }

    for warning in &report.warnings {
        eprintln!("{warning}");
    }

    if report.sessions.is_empty() {
        return Err(text.no_sessions.to_owned());
    }

    let format = cli.format.unwrap_or_default();
    let output = export_sessions(&report.sessions, format, language);
    if let Some(path) = cli.output {
        fs::write(path, output).map_err(|_| text.output_write_failed.to_owned())
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(output.as_bytes())
            .and_then(|()| stdout.flush())
            .map_err(|error| error.to_string())
    }
}

fn should_open_gui(cli: &Cli) -> bool {
    cli.gui
        || (cli.inputs.is_empty() && !cli.registry && cli.format.is_none() && cli.output.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launches_gui_when_no_cli_operation_is_requested() {
        let cli = Cli {
            inputs: Vec::new(),
            format: None,
            output: None,
            registry: false,
            gui: false,
        };
        assert!(should_open_gui(&cli));
    }

    #[test]
    fn accepts_all_inputs_in_cli_mode() {
        let cli = Cli {
            inputs: vec![PathBuf::from("one.ini"), PathBuf::from("two.ini")],
            format: None,
            output: None,
            registry: false,
            gui: false,
        };
        assert!(!should_open_gui(&cli));
        assert_eq!(cli.inputs.len(), 2);
    }

    #[test]
    fn registry_flag_selects_cli_mode_without_files() {
        let cli = Cli {
            inputs: Vec::new(),
            format: None,
            output: None,
            registry: true,
            gui: false,
        };
        assert!(!should_open_gui(&cli));
    }
}
