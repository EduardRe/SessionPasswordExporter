# Session Password Exporter

[Русская версия](README.md)

An independent Rust application for Windows 10 and 11 with a GUI and CLI. The GUI uses **egui + eframe**. Both modes share the same code for loading, parsing, and exporting WinSCP session data.

This project is not affiliated with WinSCP or its developers. The WinSCP name is used only to identify the supported configuration format.

## Project structure

```text
src/
├── main.rs              # application entry point
├── lib.rs               # shared library and public modules
├── cli.rs               # CLI arguments and GUI/CLI mode selection
├── core/                # shared models and WinSCP data processing
│   ├── crypto.rs        # WinSCP password decryption
│   ├── export.rs        # text, JSON, and XML export
│   ├── grouping.rs      # groups sessions by source files
│   ├── input.rs         # loads files and scans directories
│   ├── model.rs         # sessions, secrets, formats, and settings
│   ├── parser.rs        # parses INI files and WinSCP folder trees
│   ├── recovery.rs      # master-password search and encrypted checkpoints
│   └── registry.rs      # reads WinSCP configuration from the Windows Registry
├── config/              # constants, localization, and saved settings
└── ui/                  # egui application and session tree
    └── session_tree.rs  # renders source groups, folders, and sessions
```

Tests live beside the modules they cover using `#[cfg(test)]`, so the GUI and CLI exercise the same core implementation.

## Build and run

Run these commands from the repository root:

```powershell
cargo run                                      # launch the GUI
cargo run -- --help                            # show CLI help
cargo run -- "C:\backup\WinSCP.ini" --format json --output sessions.json
cargo run -- "C:\backup\configs" --format text
cargo run -- --registry --format xml --output sessions.xml
cargo test                                     # run tests
cargo fmt --check                              # check formatting
cargo build --release                          # optimized host build
.\scripts\build-windows-packages.ps1          # prepare tools and create packages under dist\
```

The script automatically adds any missing Rust x86/x64 targets and, when needed, downloads the official Inno Setup 7 installer, verifies its digital signature, and installs the compiler for the current user. An internet connection is required. It creates x86 and x64 executables, matching installers, one Portable ZIP with both builds, and SHA-256 checksums under `dist/`. Windows builds statically link the MSVC runtime, so a separate Visual C++ Redistributable installation is not required. The script uses the version from `Cargo.toml`; no version change is needed for a local build.

If the GUI fails to start, the app displays the error and the path to `startup.log`. The log is created beside the executable, or under `%LOCALAPPDATA%\SessionPasswordExporter\startup.log` when that folder is not writable (for example, under `Program Files`). Session contents and passwords are never written to the log.

On Windows, the GUI uses Direct3D 12 and does not require Vulkan drivers.

The CLI accepts one or more INI files or directories. In the GUI, add configurations with the file/folder pickers, drag files or folders into the window, or load sessions from the Registry. Directories are scanned recursively. Sessions are grouped by source file, displayed without the file extension, and retain WinSCP's nested folder structure. Groups and folders can be collapsed or expanded. Search filters names, hosts, and usernames as you type; an optional setting excludes collapsed groups from search. The list can be cleared. Exports in text, JSON, and XML preserve source groups.

Re-importing a file, folder, or the Registry replaces sessions from the same source instead of adding duplicates. The `×` button in the search field clears the query.

Passwords are hidden by default. Settings let you choose the password button action, language (**Русский** or **English**), and theme (**System**, **Light**, or **Dark**). Language and theme default to the operating system settings.

## GitHub Actions and releases

Pushes and pull requests to `master` run formatting, Clippy, tests, and the Windows packaging script. Every successful push to `master` also publishes a release tagged `master-<commit>`, with x86/x64 installers, the Portable ZIP, and SHA-256 checksums. The Cargo version appears in the release title and is not changed automatically. GitHub automatically attaches source-code archives to the release. Stable releases tagged `v<version>` are published separately when the matching tag is pushed. Update the version in `Cargo.toml` manually before a stable release.

Installers are per-user and do not require administrator rights. The installer lets users choose Start Menu and desktop shortcuts.

The Portable ZIP contains `x86/` and `x64/` folders. A root-level `portable.mode` marker makes both builds share `data/settings.json`. On the first portable launch, existing user settings are copied there if no portable settings file exists. Imported passwords are not saved in settings.

## Security and limitations

For configs with WinSCP master-password-protected passwords, the app offers manual password entry and password search for one config or all loaded protected configs. All three WinSCP encryption modes are supported, including legacy configs. Each source is checked separately because different files can use different master passwords.

Search runs in a background thread. Choose digits, letters, and special characters (including spaces), then set a candidate length from 1 to 100,000 characters. The progress window shows the current candidate, attempts, candidate length, speed, and elapsed time. Large ranges can take an extremely long time; the maximum supported length does not mean an exhaustive search is practically feasible.

Search progress and recovered master passwords are saved to `recovery-state.dat` before the search starts, every five seconds, and on pause, stop, and completion. Windows DPAPI encrypts the file for the current Windows account. For a regular installation, it is beside the settings file under `%APPDATA%\Session Password Exporter\session-password-exporter\config\`. In Portable mode, it is `data/recovery-state.dat`. To clear saved progress and recovered results, close the app and delete this file. Re-importing an unchanged config with the same search settings resumes the search; changed config contents reset the old result even when the path stays the same.

Master passwords entered manually remain in memory only until the app closes. Passwords recovered by search are stored only in the encrypted checkpoint, not in settings. Copy and export can skip locked configs; before continuing, the app lists which sources will be included.

Do not commit configuration files containing credentials. Exports and clipboard contents include plaintext passwords and are produced only after an explicit user action. Releases, installers, and the Portable ZIP include [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for a third-party component.

## License

This project is distributed under the standard MIT License; see [LICENSE](LICENSE). We appreciate attribution to the original project and author when reusing the code, but this is a request and not an additional license condition:

> Original repository and author: [GitHub repository](https://github.com/EduardRe/SessionPasswordExporter) — Eduard Rezunov.
