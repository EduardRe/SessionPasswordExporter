use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::time::{Duration, Instant};

use super::session_tree::{
    CollapsibleNodeId, SessionGroupView, SessionTreeAction, build_session_group_views,
    render_session_groups, session_is_in_collapsed_node,
};
use eframe::egui;
use zeroize::Zeroize;

use super::theme;
#[cfg(windows)]
use crate::config::constants::WINDOWS_WGPU_BACKENDS;
use crate::config::constants::{
    APP_LICENSE_NAME, APP_LICENSE_URL, APP_REPOSITORY_URL, APP_TITLE, APP_VERSION,
    EXPORT_FILENAME_STEM, MIN_WINDOW_HEIGHT, MIN_WINDOW_WIDTH, RECOVERY_MAXIMUM_LENGTH,
    RECOVERY_SAVE_INTERVAL_MILLIS, RECOVERY_SYMBOL_CHARSET, RECOVERY_UI_UPDATE_INTERVAL_MILLIS,
    STATUS_OUTPUT_WRITE_FAILED, STATUS_SETTINGS_WRITE_FAILED, UI_ABOUT_WINDOW_WIDTH,
    UI_BUTTON_HEIGHT, UI_ID_ABOUT_DETAILS, UI_ID_ABOUT_WINDOW, UI_ID_MASTER_PASSWORD_RESULT_WINDOW,
    UI_ID_MASTER_PASSWORD_WINDOW, UI_ID_PARTIAL_EXPORT_WINDOW, UI_ID_RECOVERY_WINDOW,
    UI_LAYOUT_GAP, UI_MASTER_PASSWORD_WINDOW_WIDTH, UI_MENU_BUTTON_PADDING_X,
    UI_MENU_BUTTON_PADDING_Y, UI_MENU_ITEM_GAP_X, UI_MENU_ITEM_GAP_Y, UI_MENU_ITEM_HEIGHT,
    UI_MENU_MARGIN, UI_MENU_SUBMENU_GAP, UI_META_SIZE, UI_RECOVERY_LIST_MAX_HEIGHT,
    UI_RECOVERY_SOURCE_ROW_HEIGHT, UI_SECTION_SIZE, UI_SETTINGS_SUBMENU_MIN_WIDTH,
    UI_SETTINGS_SWITCH_MENU_MIN_WIDTH, UI_STATUS_INDICATOR, UI_TITLE_SIZE, WINDOW_HEIGHT,
    WINDOW_WIDTH,
};
use crate::config::localization::{Labels, Language, labels, resolve_language};
use crate::config::settings::{load_settings, save_settings};
use crate::core::export::export_sessions;
use crate::core::input::load_ini_inputs;
use crate::core::master_password::{protected_sources, unlock_protected_source};
use crate::core::model::{
    ExportFormat, ImportReport, LanguagePreference, PasswordClickAction, PasswordStatus,
    RecoverySearchSettings, SecretString, Session, Settings, ThemePreference,
};
use crate::core::recovery::{
    CandidateCursor, RecoveryCheckpoint, RecoverySourceState, checkpoint_path, keyspace_log10,
    load_checkpoint, save_checkpoint, source_fingerprint,
};
use crate::core::registry::load_registry_sessions;

pub fn run() -> eframe::Result {
    crate::diagnostics::record("Preparing GUI window and graphics backend");
    let icon = super::icon::app_icon();
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
            .with_min_inner_size([MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT])
            .with_icon(egui::IconData {
                rgba: icon.rgba,
                width: icon.width,
                height: icon.height,
            })
            .with_drag_and_drop(true),
        ..Default::default()
    };
    #[cfg(windows)]
    let native_options = configure_windows_wgpu_backends(native_options);

    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(|creation_context| {
            crate::diagnostics::record("Native window created; initializing application state");
            let app = WinScpApp::new();
            theme::configure(&creation_context.egui_ctx);
            theme::apply_preference(&creation_context.egui_ctx, app.settings.theme);
            Ok(Box::new(app))
        }),
    )
}

#[cfg(windows)]
fn configure_windows_wgpu_backends(
    mut native_options: eframe::NativeOptions,
) -> eframe::NativeOptions {
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) =
        &mut native_options.wgpu_options.wgpu_setup
    {
        setup.instance_descriptor.backends = WINDOWS_WGPU_BACKENDS;
    }
    native_options
}

struct WinScpApp {
    sessions: Vec<Session>,
    settings: Settings,
    export_format: ExportFormat,
    revealed: HashSet<usize>,
    reveal_all: bool,
    search_query: String,
    cached_search_query: Option<String>,
    cached_session_count: usize,
    cached_collapsed_nodes: HashSet<CollapsibleNodeId>,
    filtered_indices: Vec<usize>,
    filtered_index_set: HashSet<usize>,
    source_groups: Vec<SessionGroupView>,
    collapsed_nodes: HashSet<CollapsibleNodeId>,
    status: String,
    about_open: bool,
    master_passwords: HashMap<String, SecretString>,
    master_password_open: bool,
    master_password_source: Option<String>,
    master_password_input: String,
    master_password_visible: bool,
    master_password_focus_input: bool,
    master_password_error: bool,
    master_password_loading: bool,
    master_password_task_error: bool,
    master_password_worker: Option<Receiver<MasterPasswordTaskResult>>,
    master_password_result: Option<MasterPasswordResult>,
    pending_output_action: Option<OutputAction>,
    recovery_checkpoint: RecoveryCheckpoint,
    recovery_checkpoint_path: PathBuf,
    recovery_checkpoint_error: bool,
    recovery_runtime: HashMap<String, RecoveryRuntimeState>,
    recovery_worker: Option<RecoveryWorker>,
    recovery_paused: bool,
    recovery_window_open: bool,
    recovery_scope: Option<String>,
    restored_window_size: Option<egui::Vec2>,
    window_was_maximized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputAction {
    Copy,
    Export,
}

struct MasterPasswordResult {
    unlocked: Vec<String>,
    failed: Vec<String>,
}

struct MasterPasswordTaskResult {
    sessions: Vec<Session>,
    passwords: HashMap<String, SecretString>,
    result: MasterPasswordResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryStatus {
    Waiting,
    Running,
    Paused,
    Found,
    Exhausted,
}

struct RecoveryRuntimeState {
    fingerprint: String,
    status: RecoveryStatus,
    current_combination: String,
    current_length: u32,
    attempts: u64,
    elapsed_millis: u64,
    attempts_per_second: u64,
}

impl Drop for RecoveryRuntimeState {
    fn drop(&mut self) {
        self.current_combination.zeroize();
    }
}

struct RecoveryTarget {
    source: String,
    fingerprint: String,
    encrypted_passwords: Vec<String>,
}

enum RecoveryCommand {
    Pause,
    Resume,
    Stop,
}

enum RecoveryEvent {
    Update(RecoveryUpdate),
    Finished(RecoveryCheckpoint),
    CheckpointError,
}

struct RecoveryUpdate {
    source: String,
    status: RecoveryStatus,
    current_combination: String,
    current_length: u32,
    positions: Vec<u8>,
    attempts: u64,
    elapsed_millis: u64,
    attempts_per_second: u64,
    exhausted: bool,
    found_password: Option<SecretString>,
}

struct RecoveryWorker {
    commands: Sender<RecoveryCommand>,
    events: Receiver<RecoveryEvent>,
}

fn run_recovery_search(
    targets: Vec<RecoveryTarget>,
    settings: RecoverySearchSettings,
    mut checkpoint: RecoveryCheckpoint,
    checkpoint_path: PathBuf,
    commands: Receiver<RecoveryCommand>,
    events: Sender<RecoveryEvent>,
) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
        };
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    }

    let mut checkpoint_failed = false;
    let mut stopped = false;
    for target in &targets {
        checkpoint.prepare_source(&target.source, &target.fingerprint, &settings);
    }
    if save_checkpoint(&checkpoint_path, &checkpoint).is_err() {
        let _ = events.send(RecoveryEvent::CheckpointError);
        let _ = events.send(RecoveryEvent::Finished(checkpoint));
        return;
    }

    for target in targets {
        let mut state = checkpoint
            .prepare_source(&target.source, &target.fingerprint, &settings)
            .clone();
        let mut cursor = match CandidateCursor::resume(
            &settings,
            state.current_length,
            state.positions.clone(),
            state.exhausted,
        ) {
            Ok(cursor) => cursor,
            Err(_) => {
                state = RecoverySourceState {
                    fingerprint: target.fingerprint.clone(),
                    settings: settings.clone(),
                    current_length: settings.minimum_length,
                    positions: vec![0; settings.minimum_length as usize],
                    ..RecoverySourceState::default()
                };
                CandidateCursor::new(&settings).expect("validated settings before starting search")
            }
        };
        if state.found_password.is_some() {
            send_recovery_update(&events, &target.source, RecoveryStatus::Found, &state, "");
            continue;
        }
        if state.exhausted {
            send_recovery_update(
                &events,
                &target.source,
                RecoveryStatus::Exhausted,
                &state,
                "",
            );
            continue;
        }

        let mut elapsed_base = state.elapsed_millis;
        let mut segment_started = Instant::now();
        let mut last_checkpoint = Instant::now();
        let mut last_update = Instant::now();
        let mut paused = false;
        let mut initial_candidate = concise_candidate(&cursor.current_combination());
        send_recovery_update(
            &events,
            &target.source,
            RecoveryStatus::Running,
            &state,
            &initial_candidate,
        );
        initial_candidate.zeroize();

        loop {
            loop {
                match commands.try_recv() {
                    Ok(RecoveryCommand::Pause) => paused = true,
                    Ok(RecoveryCommand::Resume) => paused = false,
                    Ok(RecoveryCommand::Stop) => stopped = true,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        stopped = true;
                        break;
                    }
                }
            }

            if paused || stopped {
                state.elapsed_millis = elapsed_millis(elapsed_base, segment_started);
                state.current_length = cursor.current_length();
                state.positions = cursor.positions().to_vec();
                checkpoint
                    .sources
                    .insert(target.source.clone(), state.clone());
                if save_checkpoint(&checkpoint_path, &checkpoint).is_err() {
                    checkpoint_failed = true;
                    let _ = events.send(RecoveryEvent::CheckpointError);
                }
                send_recovery_update(&events, &target.source, RecoveryStatus::Paused, &state, "");
                if stopped {
                    break;
                }

                while paused && !stopped {
                    match commands.recv_timeout(Duration::from_millis(100)) {
                        Ok(RecoveryCommand::Resume) => {
                            paused = false;
                            elapsed_base = state.elapsed_millis;
                            segment_started = Instant::now();
                            last_checkpoint = Instant::now();
                            last_update = Instant::now();
                            let _ = events.send(RecoveryEvent::Update(RecoveryUpdate {
                                source: target.source.clone(),
                                status: RecoveryStatus::Running,
                                current_combination: String::new(),
                                current_length: cursor.current_length(),
                                positions: cursor.positions().to_vec(),
                                attempts: state.attempts,
                                elapsed_millis: state.elapsed_millis,
                                attempts_per_second: average_attempts_per_second(
                                    state.attempts,
                                    state.elapsed_millis,
                                ),
                                exhausted: false,
                                found_password: None,
                            }));
                        }
                        Ok(RecoveryCommand::Stop) => stopped = true,
                        Ok(RecoveryCommand::Pause) | Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => stopped = true,
                    }
                }
                if stopped {
                    break;
                }
                continue;
            }

            let mut candidate = cursor.current_combination();
            let mut display_candidate = concise_candidate(&candidate);
            let found = target.encrypted_passwords.first().is_some_and(|encrypted| {
                crate::core::crypto::matches_master_password(encrypted, &candidate)
                    && target.encrypted_passwords.iter().skip(1).all(|encrypted| {
                        crate::core::crypto::matches_master_password(encrypted, &candidate)
                    })
            });
            state.attempts = state.attempts.saturating_add(1);
            let current_elapsed = elapsed_millis(elapsed_base, segment_started);
            let mut found_password = None;
            if found {
                state.found_password = Some(SecretString::new(std::mem::take(&mut candidate)));
                found_password = state.found_password.clone();
            } else if !cursor.advance() {
                state.exhausted = true;
            }

            if found || state.exhausted {
                state.current_length = cursor.current_length();
                state.positions = cursor.positions().to_vec();
                state.elapsed_millis = current_elapsed;
                checkpoint
                    .sources
                    .insert(target.source.clone(), state.clone());
                if save_checkpoint(&checkpoint_path, &checkpoint).is_err() {
                    checkpoint_failed = true;
                    let _ = events.send(RecoveryEvent::CheckpointError);
                }
                if found {
                    display_candidate.zeroize();
                    display_candidate.clear();
                }
                let _ = events.send(RecoveryEvent::Update(RecoveryUpdate {
                    source: target.source.clone(),
                    status: if found {
                        RecoveryStatus::Found
                    } else {
                        RecoveryStatus::Exhausted
                    },
                    current_combination: display_candidate,
                    current_length: if found {
                        cursor.current_length()
                    } else {
                        settings.maximum_length
                    },
                    positions: cursor.positions().to_vec(),
                    attempts: state.attempts,
                    elapsed_millis: state.elapsed_millis,
                    attempts_per_second: average_attempts_per_second(
                        state.attempts,
                        state.elapsed_millis,
                    ),
                    exhausted: state.exhausted,
                    found_password,
                }));
                candidate.zeroize();
                break;
            }

            if last_update.elapsed().as_millis() >= u128::from(RECOVERY_UI_UPDATE_INTERVAL_MILLIS) {
                let _ = events.send(RecoveryEvent::Update(RecoveryUpdate {
                    source: target.source.clone(),
                    status: RecoveryStatus::Running,
                    current_combination: display_candidate,
                    current_length: cursor.current_length(),
                    positions: cursor.positions().to_vec(),
                    attempts: state.attempts,
                    elapsed_millis: current_elapsed,
                    attempts_per_second: average_attempts_per_second(
                        state.attempts,
                        current_elapsed,
                    ),
                    exhausted: false,
                    found_password: None,
                }));
                last_update = Instant::now();
            }
            candidate.zeroize();

            if last_checkpoint.elapsed().as_millis() >= u128::from(RECOVERY_SAVE_INTERVAL_MILLIS) {
                state.current_length = cursor.current_length();
                state.positions = cursor.positions().to_vec();
                state.elapsed_millis = current_elapsed;
                checkpoint
                    .sources
                    .insert(target.source.clone(), state.clone());
                if save_checkpoint(&checkpoint_path, &checkpoint).is_err() {
                    checkpoint_failed = true;
                    let _ = events.send(RecoveryEvent::CheckpointError);
                    break;
                }
                elapsed_base = state.elapsed_millis;
                segment_started = Instant::now();
                last_checkpoint = Instant::now();
            }
        }

        if stopped || checkpoint_failed {
            break;
        }
    }
    if save_checkpoint(&checkpoint_path, &checkpoint).is_err() {
        let _ = events.send(RecoveryEvent::CheckpointError);
    }
    let _ = events.send(RecoveryEvent::Finished(checkpoint));
}

fn send_recovery_update(
    events: &Sender<RecoveryEvent>,
    source: &str,
    status: RecoveryStatus,
    state: &RecoverySourceState,
    current_combination: &str,
) {
    let _ = events.send(RecoveryEvent::Update(RecoveryUpdate {
        source: source.to_owned(),
        status,
        current_combination: current_combination.to_owned(),
        current_length: state.current_length,
        positions: state.positions.clone(),
        attempts: state.attempts,
        elapsed_millis: state.elapsed_millis,
        attempts_per_second: average_attempts_per_second(state.attempts, state.elapsed_millis),
        exhausted: state.exhausted,
        found_password: state.found_password.clone(),
    }));
}

fn elapsed_millis(base: u64, segment_started: Instant) -> u64 {
    base.saturating_add(
        segment_started
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
    )
}

fn average_attempts_per_second(attempts: u64, elapsed_millis: u64) -> u64 {
    attempts
        .saturating_mul(1_000)
        .checked_div(elapsed_millis.max(1))
        .unwrap_or_default()
}

fn format_elapsed(milliseconds: u64) -> String {
    let total_seconds = milliseconds / 1_000;
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn concise_candidate(candidate: &str) -> String {
    const VISIBLE_CHARACTERS: usize = 96;
    if candidate.len() <= VISIBLE_CHARACTERS {
        return candidate.to_owned();
    }
    let edge = VISIBLE_CHARACTERS / 2;
    let end = candidate.len() - edge;
    format!(
        "{}…{}…{}",
        &candidate[..edge],
        candidate.len(),
        &candidate[end..]
    )
}

impl WinScpApp {
    fn new() -> Self {
        let (settings, warning) = load_settings();
        let recovery_checkpoint_path = checkpoint_path();
        let (recovery_checkpoint, recovery_checkpoint_error) =
            match load_checkpoint(&recovery_checkpoint_path) {
                Ok(checkpoint) => (checkpoint, false),
                Err(_) => (RecoveryCheckpoint::default(), true),
            };
        let language = resolve_language(settings.language);
        let status = match warning.as_deref() {
            Some(STATUS_SETTINGS_WRITE_FAILED) => labels(language).settings_write_failed.to_owned(),
            Some(_) => labels(language).invalid_settings.to_owned(),
            None => labels(language).no_status.to_owned(),
        };
        Self {
            sessions: Vec::new(),
            settings,
            export_format: ExportFormat::Text,
            revealed: HashSet::new(),
            reveal_all: false,
            search_query: String::new(),
            cached_search_query: None,
            cached_session_count: usize::MAX,
            cached_collapsed_nodes: HashSet::new(),
            filtered_indices: Vec::new(),
            filtered_index_set: HashSet::new(),
            source_groups: Vec::new(),
            collapsed_nodes: HashSet::new(),
            status,
            about_open: false,
            master_passwords: HashMap::new(),
            master_password_open: false,
            master_password_source: None,
            master_password_input: String::new(),
            master_password_visible: false,
            master_password_focus_input: false,
            master_password_error: false,
            master_password_loading: false,
            master_password_task_error: false,
            master_password_worker: None,
            master_password_result: None,
            pending_output_action: None,
            recovery_checkpoint,
            recovery_checkpoint_path,
            recovery_checkpoint_error,
            recovery_runtime: HashMap::new(),
            recovery_worker: None,
            recovery_paused: false,
            recovery_window_open: false,
            recovery_scope: None,
            restored_window_size: None,
            window_was_maximized: false,
        }
    }

    fn add_inputs(&mut self, paths: &[PathBuf], language: Language) {
        let report = load_ini_inputs(paths);
        self.apply_report(report, language);
    }

    fn read_registry(&mut self, language: Language) {
        match load_registry_sessions() {
            Ok(report) => self.apply_report(report, language),
            Err(_) => {
                self.status = labels(language).registry_read_failed.to_owned();
            }
        }
    }

    fn apply_report(&mut self, report: ImportReport, language: Language) {
        let imported_sources = report
            .sessions
            .iter()
            .map(|session| session.source.clone())
            .collect::<HashSet<_>>();
        let new_count = replace_sessions_by_source(&mut self.sessions, report.sessions);
        self.reconcile_recovery_sources(&imported_sources);
        self.unlock_sources_with_cached_passwords();
        self.revealed.clear();
        self.reveal_all = false;
        self.cached_search_query = None;
        self.cached_session_count = usize::MAX;
        let text = labels(language);
        self.status = format!("{} {new_count}", text.status_imported);
        if !report.warnings.is_empty() {
            self.status.push_str(&format!(
                " · {} {}",
                text.status_warnings,
                report.warnings.len()
            ));
            for warning in report.warnings {
                eprintln!("{warning}");
            }
        }
    }

    fn persist_settings(&mut self) {
        self.status = match save_settings(&self.settings) {
            Ok(()) => labels(resolve_language(self.settings.language))
                .settings_saved
                .to_owned(),
            Err(_) => labels(resolve_language(self.settings.language))
                .settings_write_failed
                .to_owned(),
        };
    }

    fn set_password_click_action(&mut self, action: PasswordClickAction, context: &egui::Context) {
        if self.settings.password_click_action != action {
            self.settings.password_click_action = action;
            self.persist_settings();
            context.request_repaint();
        }
    }

    fn set_language(&mut self, language: LanguagePreference, context: &egui::Context) {
        if self.settings.language != language {
            self.settings.language = language;
            self.persist_settings();
            context.request_repaint();
        }
    }

    fn set_theme(&mut self, preference: ThemePreference, context: &egui::Context) {
        if self.settings.theme != preference {
            self.settings.theme = preference;
            theme::apply_preference(context, preference);
            self.persist_settings();
            context.request_repaint();
        }
    }

    fn set_exclude_collapsed_from_search(&mut self, value: bool, context: &egui::Context) {
        if self.settings.exclude_collapsed_from_search != value {
            self.settings.exclude_collapsed_from_search = value;
            self.cached_search_query = None;
            self.persist_settings();
            context.request_repaint();
        }
    }

    fn clear_session_list(&mut self, language: Language) {
        self.sessions.clear();
        self.master_passwords.clear();
        self.search_query.clear();
        self.revealed.clear();
        self.reveal_all = false;
        self.filtered_indices.clear();
        self.filtered_index_set.clear();
        self.source_groups.clear();
        self.collapsed_nodes.clear();
        self.cached_collapsed_nodes.clear();
        self.cached_search_query = None;
        self.cached_session_count = usize::MAX;
        self.status = labels(language).list_cleared.to_owned();
    }

    fn remove_source_group(&mut self, source: &str, language: Language) {
        if remove_sessions_by_source(&mut self.sessions, source) == 0 {
            return;
        }

        self.master_passwords.remove(&source_identity(source));
        self.revealed.clear();
        self.reveal_all = false;
        self.collapsed_nodes.retain(|node| match node {
            CollapsibleNodeId::Source(node_source)
            | CollapsibleNodeId::Folder {
                source: node_source,
                ..
            } => node_source != source,
        });
        self.cached_collapsed_nodes.retain(|node| match node {
            CollapsibleNodeId::Source(node_source)
            | CollapsibleNodeId::Folder {
                source: node_source,
                ..
            } => node_source != source,
        });
        self.filtered_indices.clear();
        self.filtered_index_set.clear();
        self.source_groups.clear();
        self.cached_search_query = None;
        self.cached_session_count = usize::MAX;
        self.status = labels(language).status_group_removed.to_owned();
    }

    fn clear_search(&mut self) {
        self.search_query.clear();
        self.cached_search_query = None;
    }

    fn copy_all(&mut self, context: &egui::Context, language: Language) {
        let exportable = self.exportable_sessions();
        let mut output = export_sessions(&exportable, self.export_format, language);
        context.copy_text(output.clone());
        output.zeroize();
        self.status = labels(language).status_exported.to_owned();
    }

    fn save_export(&mut self, language: Language) {
        let text = labels(language);
        let filename = format!("{EXPORT_FILENAME_STEM}.{}", self.export_format.extension());
        let path = egui_file_dialog(text, self.export_format, &filename);
        let Some(path) = path else {
            return;
        };
        let exportable = self.exportable_sessions();
        let mut output = export_sessions(&exportable, self.export_format, language);
        self.status = match fs::write(path, &output) {
            Ok(()) => text.status_saved.to_owned(),
            Err(_) => STATUS_OUTPUT_WRITE_FAILED.to_owned(),
        };
        output.zeroize();
    }

    fn request_output(&mut self, action: OutputAction) {
        if protected_sources(&self.sessions).is_empty() {
            self.pending_output_action = None;
        } else {
            self.pending_output_action = Some(action);
        }
    }

    fn perform_output(
        &mut self,
        action: OutputAction,
        context: &egui::Context,
        language: Language,
    ) {
        match action {
            OutputAction::Copy => self.copy_all(context, language),
            OutputAction::Export => self.save_export(language),
        }
    }

    fn exportable_sessions(&self) -> Vec<Session> {
        filter_exportable_sessions(&self.sessions)
    }

    fn reconcile_recovery_sources(&mut self, sources: &HashSet<String>) {
        reconcile_recovery_state(
            &mut self.recovery_checkpoint,
            &mut self.recovery_runtime,
            &self.sessions,
            sources,
        );
    }

    fn unlock_sources_with_cached_passwords(&mut self) {
        let sources = protected_sources(&self.sessions);
        let active_sources = self
            .sessions
            .iter()
            .map(|session| session.source.as_str())
            .collect::<HashSet<_>>();
        let active_keys = active_sources
            .into_iter()
            .map(source_identity)
            .collect::<HashSet<_>>();
        self.master_passwords
            .retain(|source, _| active_keys.contains(source));

        for source in sources {
            let key = source_identity(&source);
            if !self.master_passwords.contains_key(&key)
                && let Some(state) = self.recovery_checkpoint.sources.get(&source)
                && state.fingerprint == source_fingerprint(&source, &self.sessions)
                && let Some(password) = state.found_password.as_ref()
            {
                self.master_passwords.insert(key.clone(), password.clone());
            }
            let Some(mut password) = self
                .master_passwords
                .get(&key)
                .map(|password| password.as_str().to_owned())
            else {
                continue;
            };
            if !unlock_protected_source(&mut self.sessions, &source, &password) {
                self.master_passwords.remove(&key);
            }
            password.zeroize();
        }
        self.cached_search_query = None;
        self.cached_session_count = usize::MAX;
    }

    fn begin_decrypt_protected_configs(&mut self, language: Language) {
        if self.master_password_loading {
            return;
        }
        self.master_password_error = false;
        self.master_password_task_error = false;
        if self.master_password_input.is_empty() {
            self.master_password_error = true;
            return;
        }

        let mut sessions = self.sessions.clone();
        let mut passwords = self.master_passwords.clone();
        let sources =
            protected_sources_for_scope(&sessions, self.master_password_source.as_deref());
        if sources.is_empty() {
            self.master_password_task_error = true;
            return;
        }
        let password = SecretString::new(std::mem::take(&mut self.master_password_input));
        let source_names = source_display_name_map(&sources, labels(language));
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("master-password-decryption".to_owned())
            .spawn(move || {
                let mut result = MasterPasswordResult {
                    unlocked: Vec::new(),
                    failed: Vec::new(),
                };
                for source in sources {
                    let identity = source_identity(&source);
                    if unlock_protected_source(&mut sessions, &source, password.as_str()) {
                        passwords.insert(identity, SecretString::new(password.as_str().to_owned()));
                        result.unlocked.push(source_names[&source].clone());
                    } else {
                        passwords.remove(&identity);
                        result.failed.push(source_names[&source].clone());
                    }
                }
                let _ = sender.send(MasterPasswordTaskResult {
                    sessions,
                    passwords,
                    result,
                });
            });

        match worker {
            Ok(_) => {
                self.master_password_worker = Some(receiver);
                self.master_password_loading = true;
                self.master_password_visible = false;
            }
            Err(_) => {
                self.master_password_task_error = true;
            }
        }
    }

    fn poll_master_password_decryption(&mut self, context: &egui::Context) {
        let received = self.master_password_worker.as_ref().map(Receiver::try_recv);
        match received {
            Some(Ok(task_result)) => {
                self.sessions = task_result.sessions;
                self.master_passwords = task_result.passwords;
                self.master_password_result = Some(task_result.result);
                self.master_password_worker = None;
                self.master_password_loading = false;
                self.master_password_open = false;
                self.master_password_source = None;
                self.master_password_focus_input = false;
                self.master_password_input.zeroize();
                self.master_password_input.clear();
                self.cached_search_query = None;
                self.cached_session_count = usize::MAX;
            }
            Some(Err(TryRecvError::Empty)) => {
                context.request_repaint_after(std::time::Duration::from_millis(100));
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.master_password_worker = None;
                self.master_password_loading = false;
                self.master_password_task_error = true;
            }
            None => {}
        }
    }

    fn open_master_password_dialog(&mut self, source: Option<String>) {
        self.master_password_input.zeroize();
        self.master_password_input.clear();
        self.master_password_error = false;
        self.master_password_task_error = false;
        self.master_password_visible = false;
        self.master_password_focus_input = true;
        self.master_password_source = source;
        self.master_password_open = true;
    }

    fn open_recovery_window(&mut self, source: Option<String>) {
        self.recovery_scope = source;
        self.recovery_window_open = true;
    }

    fn start_recovery(&mut self, language: Language) {
        if self.recovery_worker.is_some() {
            return;
        }
        let settings = self.settings.recovery_search.clone();
        if CandidateCursor::new(&settings).is_err() {
            self.status = labels(language).recovery_invalid_settings.to_owned();
            return;
        }
        let sources = protected_sources_for_scope(&self.sessions, self.recovery_scope.as_deref());
        let targets = sources
            .into_iter()
            .filter_map(|source| {
                let encrypted_passwords = self
                    .sessions
                    .iter()
                    .filter(|session| {
                        session.source == source && session.encrypted_password.is_some()
                    })
                    .filter_map(|session| session.encrypted_password.as_ref())
                    .map(|password| password.as_str().to_owned())
                    .collect::<Vec<_>>();
                if encrypted_passwords.is_empty() {
                    return None;
                }
                let fingerprint = source_fingerprint(&source, &self.sessions);
                Some(RecoveryTarget {
                    source,
                    fingerprint,
                    encrypted_passwords,
                })
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            self.status = labels(language).recovery_no_protected.to_owned();
            return;
        }
        self.recovery_checkpoint_error = false;

        for target in &targets {
            self.recovery_runtime.insert(
                target.source.clone(),
                RecoveryRuntimeState {
                    fingerprint: target.fingerprint.clone(),
                    status: RecoveryStatus::Waiting,
                    current_combination: String::new(),
                    current_length: self
                        .recovery_checkpoint
                        .sources
                        .get(&target.source)
                        .map(|state| state.current_length)
                        .unwrap_or(settings.minimum_length),
                    attempts: self
                        .recovery_checkpoint
                        .sources
                        .get(&target.source)
                        .map(|state| state.attempts)
                        .unwrap_or_default(),
                    elapsed_millis: self
                        .recovery_checkpoint
                        .sources
                        .get(&target.source)
                        .map(|state| state.elapsed_millis)
                        .unwrap_or_default(),
                    attempts_per_second: 0,
                },
            );
        }

        let (command_sender, command_receiver) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        let checkpoint = self.recovery_checkpoint.clone();
        let checkpoint_path = self.recovery_checkpoint_path.clone();
        let worker = std::thread::Builder::new()
            .name("master-password-recovery".to_owned())
            .spawn(move || {
                run_recovery_search(
                    targets,
                    settings,
                    checkpoint,
                    checkpoint_path,
                    command_receiver,
                    event_sender,
                );
            });
        match worker {
            Ok(_) => {
                self.recovery_worker = Some(RecoveryWorker {
                    commands: command_sender,
                    events: event_receiver,
                });
                self.recovery_paused = false;
                self.status = labels(language).recovery_title.to_owned();
            }
            Err(_) => {
                self.status = labels(language).master_password_task_failed.to_owned();
            }
        }
    }

    fn poll_recovery_worker(&mut self, context: &egui::Context, language: Language) {
        let mut received = Vec::new();
        let mut worker_disconnected = false;
        if let Some(worker) = self.recovery_worker.as_ref() {
            loop {
                match worker.events.try_recv() {
                    Ok(event) => received.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        worker_disconnected = true;
                        break;
                    }
                }
            }
        }

        let mut finished = false;
        for event in received {
            match event {
                RecoveryEvent::Update(update) => {
                    let fingerprint = self
                        .recovery_runtime
                        .get(&update.source)
                        .map(|runtime| runtime.fingerprint.clone())
                        .unwrap_or_default();
                    let state = self
                        .recovery_checkpoint
                        .sources
                        .entry(update.source.clone())
                        .or_default();
                    if state.fingerprint.is_empty()
                        && let Some(runtime) = self.recovery_runtime.get(&update.source)
                    {
                        state.fingerprint.clone_from(&runtime.fingerprint);
                        state.settings = self.settings.recovery_search.clone();
                    }
                    state.current_length = update.current_length;
                    state.positions = update.positions;
                    state.attempts = update.attempts;
                    state.elapsed_millis = update.elapsed_millis;
                    state.exhausted = update.exhausted;
                    if let Some(password) = update.found_password {
                        state.found_password = Some(password.clone());
                        if unlock_protected_source(
                            &mut self.sessions,
                            &update.source,
                            password.as_str(),
                        ) {
                            self.master_passwords
                                .insert(source_identity(&update.source), password);
                            self.cached_search_query = None;
                            self.cached_session_count = usize::MAX;
                        }
                    }
                    self.recovery_runtime.insert(
                        update.source,
                        RecoveryRuntimeState {
                            fingerprint,
                            status: update.status,
                            current_combination: update.current_combination,
                            current_length: update.current_length,
                            attempts: update.attempts,
                            elapsed_millis: update.elapsed_millis,
                            attempts_per_second: update.attempts_per_second,
                        },
                    );
                }
                RecoveryEvent::Finished(checkpoint) => {
                    self.recovery_checkpoint = checkpoint;
                    finished = true;
                }
                RecoveryEvent::CheckpointError => {
                    self.recovery_checkpoint_error = true;
                    self.status = labels(language).recovery_checkpoint_failed.to_owned();
                }
            }
        }
        finished |= worker_disconnected;
        if finished {
            self.recovery_worker = None;
            self.recovery_paused = false;
            if !self.recovery_checkpoint_error {
                self.status = labels(language).no_status.to_owned();
            }
        } else if self.recovery_worker.is_some() {
            context
                .request_repaint_after(Duration::from_millis(RECOVERY_UI_UPDATE_INTERVAL_MILLIS));
        }
    }

    fn set_recovery_paused(&mut self, paused: bool) {
        if let Some(worker) = &self.recovery_worker {
            let command = if paused {
                RecoveryCommand::Pause
            } else {
                RecoveryCommand::Resume
            };
            let _ = worker.commands.send(command);
            self.recovery_paused = paused;
        }
    }

    fn stop_recovery(&mut self) {
        if let Some(worker) = &self.recovery_worker {
            let _ = worker.commands.send(RecoveryCommand::Stop);
        }
    }

    fn show_recovery_window(
        &mut self,
        context: &egui::Context,
        window_id: egui::Id,
        text: &Labels,
        language: Language,
    ) {
        let mut is_open = self.recovery_window_open;
        let mut start = false;
        let mut pause = false;
        let mut resume = false;
        let mut stop = false;
        let mut settings_changed = false;

        if is_open {
            egui::Window::new(text.recovery_title)
                .id(window_id)
                .default_width(UI_MASTER_PASSWORD_WINDOW_WIDTH + 180.0)
                .default_pos(context.content_rect().center())
                .pivot(egui::Align2::CENTER_CENTER)
                .collapsible(false)
                .resizable(true)
                .open(&mut is_open)
                .show(context, |ui| {
                    ui.label(
                        egui::RichText::new(text.recovery_settings)
                            .strong()
                            .color(theme::palette(ui).text),
                    );
                    let is_running = self.recovery_worker.is_some();
                    ui.add_enabled_ui(!is_running, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            settings_changed |= ui
                                .checkbox(
                                    &mut self.settings.recovery_search.digits,
                                    text.recovery_digits,
                                )
                                .changed();
                            settings_changed |= ui
                                .checkbox(
                                    &mut self.settings.recovery_search.letters,
                                    text.recovery_letters,
                                )
                                .changed();
                            settings_changed |= ui
                                .checkbox(
                                    &mut self.settings.recovery_search.symbols,
                                    text.recovery_symbols,
                                )
                                .changed();
                        });
                        ui.monospace(
                            egui::RichText::new(RECOVERY_SYMBOL_CHARSET)
                                .color(theme::palette(ui).muted),
                        );
                        ui.label(
                            egui::RichText::new(text.recovery_space_included)
                                .size(UI_META_SIZE)
                                .color(theme::palette(ui).muted),
                        );
                        ui.horizontal(|ui| {
                            ui.label(text.recovery_minimum_length);
                            settings_changed |= ui
                                .add(
                                    egui::DragValue::new(
                                        &mut self.settings.recovery_search.minimum_length,
                                    )
                                    .range(1..=RECOVERY_MAXIMUM_LENGTH),
                                )
                                .changed();
                            ui.label(text.recovery_maximum_length);
                            settings_changed |= ui
                                .add(
                                    egui::DragValue::new(
                                        &mut self.settings.recovery_search.maximum_length,
                                    )
                                    .range(1..=RECOVERY_MAXIMUM_LENGTH),
                                )
                                .changed();
                        });
                    });
                    if let Some(log10) = keyspace_log10(&self.settings.recovery_search) {
                        ui.label(format!("{} 10^{log10:.2}", text.recovery_keyspace));
                    }
                    if self.settings.recovery_search.minimum_length
                        > self.settings.recovery_search.maximum_length
                    {
                        self.settings.recovery_search.maximum_length =
                            self.settings.recovery_search.minimum_length;
                        settings_changed = true;
                    }
                    if CandidateCursor::new(&self.settings.recovery_search).is_err() {
                        ui.label(
                            egui::RichText::new(text.recovery_invalid_settings)
                                .color(theme::palette(ui).error),
                        );
                    }
                    if self.recovery_checkpoint_error {
                        ui.label(
                            egui::RichText::new(text.recovery_checkpoint_failed)
                                .color(theme::palette(ui).error),
                        );
                    }
                    ui.add_space(UI_LAYOUT_GAP / 2.0);

                    ui.horizontal(|ui| {
                        if self.recovery_worker.is_none() {
                            let label = if self.recovery_scope.is_some() {
                                text.recovery_start
                            } else {
                                text.recovery_start_all
                            };
                            ui.add_enabled_ui(
                                CandidateCursor::new(&self.settings.recovery_search).is_ok(),
                                |ui| {
                                    if theme::primary_button(ui, label).clicked() {
                                        start = true;
                                    }
                                },
                            );
                        } else {
                            ui.add(egui::Spinner::new().color(theme::palette(ui).accent));
                            let toggle_label = if self.recovery_paused {
                                text.recovery_resume
                            } else {
                                text.recovery_pause
                            };
                            if theme::secondary_button(ui, toggle_label).clicked() {
                                if self.recovery_paused {
                                    resume = true;
                                } else {
                                    pause = true;
                                }
                            }
                            if theme::secondary_button(ui, text.recovery_stop).clicked() {
                                stop = true;
                            }
                        }
                    });

                    let mut sources = self
                        .recovery_checkpoint
                        .sources
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>();
                    sources.extend(self.recovery_runtime.keys().cloned());
                    sources.sort_unstable();
                    sources.dedup();
                    egui::ScrollArea::vertical()
                        .max_height(UI_RECOVERY_LIST_MAX_HEIGHT)
                        .show_rows(
                            ui,
                            UI_RECOVERY_SOURCE_ROW_HEIGHT,
                            sources.len(),
                            |ui, visible_rows| {
                                for row_index in visible_rows {
                                    let source = &sources[row_index];
                                    let runtime = self.recovery_runtime.get(source);
                                    let checkpoint_state =
                                        self.recovery_checkpoint.sources.get(source);
                                    if runtime.is_none() && checkpoint_state.is_none() {
                                        continue;
                                    }
                                    let fallback_state = RecoverySourceState {
                                        fingerprint: runtime
                                            .map(|value| value.fingerprint.clone())
                                            .unwrap_or_default(),
                                        settings: self.settings.recovery_search.clone(),
                                        current_length: runtime
                                            .map(|value| value.current_length)
                                            .unwrap_or(
                                                self.settings.recovery_search.minimum_length,
                                            ),
                                        attempts: runtime
                                            .map(|value| value.attempts)
                                            .unwrap_or_default(),
                                        elapsed_millis: runtime
                                            .map(|value| value.elapsed_millis)
                                            .unwrap_or_default(),
                                        ..RecoverySourceState::default()
                                    };
                                    let state = checkpoint_state.unwrap_or(&fallback_state);
                                    theme::card_frame(ui).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new(source_display_name(
                                                    source, text,
                                                ))
                                                .strong()
                                                .color(theme::palette(ui).text),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    let status = self
                                                        .recovery_runtime
                                                        .get(source)
                                                        .map(|value| value.status)
                                                        .unwrap_or_else(|| {
                                                            if state.found_password.is_some() {
                                                                RecoveryStatus::Found
                                                            } else if state.exhausted {
                                                                RecoveryStatus::Exhausted
                                                            } else {
                                                                RecoveryStatus::Waiting
                                                            }
                                                        });
                                                    let status_label = match status {
                                                        RecoveryStatus::Waiting => {
                                                            text.recovery_waiting
                                                        }
                                                        RecoveryStatus::Running => {
                                                            text.recovery_status_running
                                                        }
                                                        RecoveryStatus::Paused => {
                                                            text.recovery_status_paused
                                                        }
                                                        RecoveryStatus::Found => {
                                                            text.recovery_found
                                                        }
                                                        RecoveryStatus::Exhausted => {
                                                            text.recovery_exhausted
                                                        }
                                                    };
                                                    ui.label(status_label);
                                                },
                                            );
                                        });
                                        ui.add_sized(
                                            [ui.available_width(), UI_META_SIZE + 4.0],
                                            egui::Label::new(
                                                egui::RichText::new(source)
                                                    .size(UI_META_SIZE)
                                                    .color(theme::palette(ui).muted),
                                            )
                                            .truncate(),
                                        );
                                        let attempts = runtime
                                            .map(|value| value.attempts)
                                            .unwrap_or(state.attempts);
                                        let current_length = runtime
                                            .map(|value| value.current_length)
                                            .unwrap_or(state.current_length);
                                        let elapsed = runtime
                                            .map(|value| value.elapsed_millis)
                                            .unwrap_or(state.elapsed_millis);
                                        let speed = runtime
                                            .map(|value| value.attempts_per_second)
                                            .unwrap_or_else(|| {
                                                average_attempts_per_second(attempts, elapsed)
                                            });
                                        ui.horizontal_wrapped(|ui| {
                                            ui.label(format!(
                                                "{} {attempts}",
                                                text.recovery_attempts
                                            ));
                                            ui.label(format!(
                                                "{} {current_length}",
                                                text.recovery_length
                                            ));
                                            ui.label(format!(
                                                "{} {}",
                                                text.recovery_elapsed,
                                                format_elapsed(elapsed)
                                            ));
                                            ui.label(format!("{} {speed}", text.recovery_speed));
                                        });
                                        let mut candidate = runtime
                                            .map(|value| value.current_combination.clone())
                                            .filter(|value| !value.is_empty())
                                            .or_else(|| {
                                                (state.attempts > 0
                                                    && !state.exhausted
                                                    && state.found_password.is_none())
                                                .then(|| {
                                                    CandidateCursor::resume(
                                                        &state.settings,
                                                        state.current_length,
                                                        state.positions.clone(),
                                                        false,
                                                    )
                                                    .ok()
                                                    .map(|cursor| {
                                                        concise_candidate(
                                                            &cursor.current_combination(),
                                                        )
                                                    })
                                                })
                                                .flatten()
                                            })
                                            .unwrap_or_default();
                                        ui.horizontal(|ui| {
                                            ui.label(text.recovery_combination);
                                            ui.add_sized(
                                                [ui.available_width(), UI_BUTTON_HEIGHT],
                                                egui::TextEdit::singleline(&mut candidate)
                                                    .interactive(false),
                                            );
                                        });
                                        candidate.zeroize();
                                        if let Some(password) = state.found_password.as_ref() {
                                            ui.horizontal(|ui| {
                                                ui.monospace(password.as_str());
                                                if theme::secondary_button(ui, text.recovery_copy)
                                                    .clicked()
                                                {
                                                    context.copy_text(password.as_str().to_owned());
                                                }
                                            });
                                        }
                                    });
                                }
                            },
                        );
                });
        }

        self.recovery_window_open = is_open;
        if settings_changed {
            self.persist_settings();
        }
        if start {
            self.start_recovery(language);
        }
        if pause {
            self.set_recovery_paused(true);
        }
        if resume {
            self.set_recovery_paused(false);
        }
        if stop {
            self.stop_recovery();
        }
    }

    fn click_password_action(&mut self, index: usize, context: &egui::Context) {
        let Some(session) = self.sessions.get(index) else {
            return;
        };
        if session.password_status != PasswordStatus::Available {
            return;
        }

        let currently_visible = self.reveal_all || self.revealed.contains(&index);
        let action = self.settings.password_click_action;
        let should_copy = should_copy_password(action, currently_visible);
        let mut clipboard_text = should_copy.then(|| session.password.as_str().to_owned());

        match action {
            PasswordClickAction::Show => self.toggle_reveal(index, currently_visible),
            PasswordClickAction::Copy => {}
            PasswordClickAction::ShowAndCopy => self.toggle_reveal(index, currently_visible),
        }
        if let Some(value) = clipboard_text.as_mut() {
            context.copy_text(value.clone());
            value.zeroize();
        }
    }

    fn toggle_reveal(&mut self, index: usize, currently_visible: bool) {
        toggle_session_visibility(
            &mut self.reveal_all,
            &mut self.revealed,
            index,
            self.sessions.len(),
            currently_visible,
        );
    }

    fn update_session_list_cache(&mut self) {
        let query_changed = self.cached_search_query.as_deref() != Some(self.search_query.as_str());
        let session_count_changed = self.cached_session_count != self.sessions.len();
        let search_active = !self.search_query.trim().is_empty();
        let exclude_collapsed = self.settings.exclude_collapsed_from_search && search_active;

        if query_changed && search_active && !self.settings.exclude_collapsed_from_search {
            self.collapsed_nodes.clear();
        }

        let collapsed_filter_changed =
            exclude_collapsed && self.cached_collapsed_nodes != self.collapsed_nodes;
        if !query_changed && !session_count_changed && !collapsed_filter_changed {
            return;
        }

        if session_count_changed {
            let all_indices = (0..self.sessions.len()).collect::<Vec<_>>();
            self.source_groups = build_session_group_views(&self.sessions, &all_indices);
        }
        self.filtered_indices = filter_session_indices(
            &self.sessions,
            &self.search_query,
            exclude_collapsed,
            &self.collapsed_nodes,
        );
        self.filtered_index_set = self.filtered_indices.iter().copied().collect();
        self.cached_search_query = Some(self.search_query.clone());
        self.cached_session_count = self.sessions.len();
        self.cached_collapsed_nodes
            .clone_from(&self.collapsed_nodes);
    }
}

impl eframe::App for WinScpApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        static FIRST_FRAME: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        FIRST_FRAME.get_or_init(|| crate::diagnostics::record("First GUI frame rendered"));
        let context = ui.ctx().clone();
        correct_restored_window(self, &context);
        let language = resolve_language(self.settings.language);
        let text = labels(language);
        self.poll_master_password_decryption(&context);
        self.poll_recovery_worker(&context, language);
        let drag_active = context.input(|input| !input.raw.hovered_files.is_empty());
        let dropped_paths = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .collect::<Vec<_>>()
        });
        if !self.master_password_loading
            && !self.master_password_open
            && self.recovery_worker.is_none()
            && !dropped_paths.is_empty()
        {
            self.add_inputs(&dropped_paths, language);
        }

        self.update_session_list_cache();
        let session_count = if self.search_query.trim().is_empty() {
            format!("{} {}", text.session_count_prefix, self.sessions.len())
        } else {
            format!(
                "{} {}/{}",
                text.session_count_prefix,
                self.filtered_indices.len(),
                self.sessions.len()
            )
        };
        let chrome = theme::chrome_panel_frame(ui);

        egui::Panel::top("header").frame(chrome).show(ui, |ui| {
            theme::card_frame(ui).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(text.header_title)
                            .size(UI_TITLE_SIZE)
                            .strong()
                            .color(theme::palette(ui).text),
                    )
                    .on_hover_text(text.header_subtitle);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::menu::MenuButton::new(text.settings)
                            .config(settings_menu_config())
                            .ui(ui, |ui| settings_menu(ui, self, text, &context));
                        theme::badge(ui, &session_count);
                    });
                });
            });
        });

        egui::Panel::top("toolbar").frame(chrome).show(ui, |ui| {
            theme::card_frame(ui).show(ui, |ui| {
                if self.recovery_worker.is_some() {
                    ui.horizontal(|ui| {
                        ui.label(if self.recovery_paused {
                            text.recovery_status_paused
                        } else {
                            text.recovery_status_running
                        });
                        if theme::secondary_button(ui, text.recovery_title).clicked() {
                            self.recovery_window_open = true;
                        }
                    });
                }
                ui.add_enabled_ui(
                    !self.master_password_loading
                        && !self.master_password_open
                        && self.recovery_worker.is_none(),
                    |ui| {
                        ui.horizontal_wrapped(|ui| {
                            if theme::primary_button(ui, text.add_files).clicked()
                                && let Some(paths) = pick_ini_files(text)
                            {
                                self.add_inputs(&paths, language);
                            }
                            if theme::secondary_button(ui, text.add_folder).clicked()
                                && let Some(path) = pick_ini_folder(text)
                            {
                                self.add_inputs(&[path], language);
                            }
                            if theme::secondary_button(ui, text.read_registry).clicked() {
                                self.read_registry(language);
                            }
                            if !self.sessions.is_empty()
                                && theme::secondary_button(ui, text.clear_list).clicked()
                            {
                                self.clear_session_list(language);
                            }
                            if self.recovery_worker.is_none()
                                && self
                                    .sessions
                                    .iter()
                                    .any(|session| session.encrypted_password.is_some())
                                && theme::secondary_button(ui, text.master_password_button)
                                    .clicked()
                            {
                                self.open_master_password_dialog(None);
                            }
                            if self.recovery_worker.is_none()
                                && self
                                    .sessions
                                    .iter()
                                    .any(|session| session.encrypted_password.is_some())
                                && theme::secondary_button(ui, text.recovery_start_all).clicked()
                            {
                                self.open_recovery_window(None);
                            }

                            if !self.sessions.is_empty() {
                                ui.separator();
                                ui.label(text.export_format);
                                egui::ComboBox::from_id_salt(
                                    crate::config::constants::UI_ID_EXPORT_FORMAT,
                                )
                                .selected_text(export_format_label(self.export_format, text))
                                .show_ui(ui, |ui| {
                                    for format in
                                        [ExportFormat::Text, ExportFormat::Json, ExportFormat::Xml]
                                    {
                                        ui.selectable_value(
                                            &mut self.export_format,
                                            format,
                                            export_format_label(format, text),
                                        );
                                    }
                                });

                                let reveal_label = if self.reveal_all {
                                    text.hide_all
                                } else {
                                    text.show_all
                                };
                                if theme::secondary_button(ui, reveal_label).clicked() {
                                    self.reveal_all = !self.reveal_all;
                                    self.revealed.clear();
                                }
                                if theme::secondary_button(ui, text.copy_all).clicked() {
                                    self.request_output(OutputAction::Copy);
                                    if self.pending_output_action.is_none() {
                                        self.perform_output(OutputAction::Copy, &context, language);
                                    }
                                }
                                if theme::secondary_button(ui, text.save_export).clicked() {
                                    self.request_output(OutputAction::Export);
                                    if self.pending_output_action.is_none() {
                                        self.perform_output(
                                            OutputAction::Export,
                                            &context,
                                            language,
                                        );
                                    }
                                }
                            }
                        });
                    },
                );
            });
        });

        egui::Panel::bottom("status").frame(chrome).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(UI_STATUS_INDICATOR)
                        .size(UI_META_SIZE)
                        .color(theme::palette(ui).success),
                );
                ui.label(
                    egui::RichText::new(if self.status.is_empty() {
                        text.no_status
                    } else {
                        &self.status
                    })
                    .size(UI_META_SIZE)
                    .color(theme::palette(ui).muted),
                );
            });
        });

        egui::CentralPanel::default().frame(chrome).show(ui, |ui| {
            if self.sessions.is_empty() {
                ui.centered_and_justified(|ui| {
                    theme::card_frame(ui).show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new(text.empty_title)
                                    .size(UI_SECTION_SIZE)
                                    .strong(),
                            );
                            ui.add_space(UI_LAYOUT_GAP);
                            ui.label(
                                egui::RichText::new(text.empty_hint)
                                    .color(theme::palette(ui).muted),
                            );
                            ui.add_space(UI_LAYOUT_GAP);
                            if theme::primary_button(ui, text.add_files).clicked()
                                && let Some(paths) = pick_ini_files(text)
                            {
                                self.add_inputs(&paths, language);
                            }
                        });
                    });
                });
                return;
            }

            ui.horizontal(|ui| {
                let clear_button_width = if self.search_query.is_empty() {
                    0.0
                } else {
                    UI_BUTTON_HEIGHT + UI_LAYOUT_GAP
                };
                let search_width = (ui.available_width() - clear_button_width).max(0.0);
                ui.add_sized(
                    [search_width, UI_BUTTON_HEIGHT],
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text(text.search_placeholder),
                );
                if !self.search_query.is_empty()
                    && theme::secondary_button(ui, "×")
                        .on_hover_text(text.clear_search)
                        .clicked()
                {
                    self.clear_search();
                }
            });

            let search_active = !self.search_query.trim().is_empty();
            if self.filtered_indices.is_empty()
                && !(search_active && self.settings.exclude_collapsed_from_search)
            {
                ui.label(
                    egui::RichText::new(text.search_no_results).color(theme::palette(ui).muted),
                );
                return;
            }

            let mut actions = Vec::new();
            let rendered_rows = ui
                .add_enabled_ui(
                    !self.master_password_loading
                        && !self.master_password_open
                        && self.recovery_worker.is_none(),
                    |ui| {
                        render_session_groups(
                            ui,
                            &self.source_groups,
                            &self.sessions,
                            &self.filtered_index_set,
                            search_active,
                            self.settings.exclude_collapsed_from_search,
                            &self.revealed,
                            self.reveal_all,
                            self.settings.password_click_action,
                            text,
                            language,
                            &mut self.collapsed_nodes,
                            &mut actions,
                        )
                    },
                )
                .inner;
            if self.filtered_indices.is_empty() && !rendered_rows {
                ui.label(
                    egui::RichText::new(text.search_no_results).color(theme::palette(ui).muted),
                );
            }
            let mut removals = Vec::new();
            for action in actions {
                match action {
                    SessionTreeAction::Password(index) => {
                        self.click_password_action(index, &context);
                    }
                    SessionTreeAction::EnterMasterPassword(source) => {
                        self.open_master_password_dialog(Some(source));
                    }
                    SessionTreeAction::StartRecovery(source) => {
                        self.open_recovery_window(Some(source));
                    }
                    SessionTreeAction::RemoveSource(source) => removals.push(source),
                }
            }
            for source in removals {
                self.remove_source_group(&source, language);
            }
        });

        if drag_active {
            theme::drop_target_overlay(ui, text.drop_hint);
        }

        let mut about_open = self.about_open;
        if about_open {
            egui::Window::new(text.about)
                .id(ui.scope_id().with(UI_ID_ABOUT_WINDOW))
                .default_width(UI_ABOUT_WINDOW_WIDTH)
                .default_pos(context.content_rect().center())
                .pivot(egui::Align2::CENTER_CENTER)
                .collapsible(false)
                .open(&mut about_open)
                .show(&context, |ui| about_window(ui, text));
        }
        self.about_open = about_open;

        let mut password_window_open = self.master_password_open;
        let mut start_decryption = false;
        if password_window_open {
            let mut close_password_window = false;
            egui::Window::new(text.master_password_title)
                .id(ui.scope_id().with(UI_ID_MASTER_PASSWORD_WINDOW))
                .default_width(UI_MASTER_PASSWORD_WINDOW_WIDTH)
                .default_pos(context.content_rect().center())
                .pivot(egui::Align2::CENTER_CENTER)
                .collapsible(false)
                .resizable(false)
                .open(&mut password_window_open)
                .show(&context, |ui| {
                    if self.master_password_loading {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().color(theme::palette(ui).accent));
                            ui.label(text.master_password_working);
                        });
                    } else {
                        ui.label(text.master_password_field);
                        ui.horizontal(|ui| {
                            let password_response = ui.add_sized(
                                [ui.available_width() - 112.0, UI_BUTTON_HEIGHT],
                                egui::TextEdit::singleline(&mut self.master_password_input)
                                    .password(!self.master_password_visible),
                            );
                            if self.master_password_focus_input {
                                password_response.request_focus();
                                self.master_password_focus_input = false;
                            }
                            let visibility_label = if self.master_password_visible {
                                text.master_password_hide
                            } else {
                                text.master_password_show
                            };
                            if theme::secondary_button(ui, visibility_label).clicked() {
                                self.master_password_visible = !self.master_password_visible;
                            }
                            if should_submit_master_password(
                                password_response.lost_focus(),
                                ui.input(|input| input.key_pressed(egui::Key::Enter)),
                            ) {
                                start_decryption = true;
                            }
                        });
                        if self.master_password_error {
                            ui.label(
                                egui::RichText::new(text.master_password_empty)
                                    .color(theme::palette(ui).error),
                            );
                        }
                        if self.master_password_task_error {
                            ui.label(
                                egui::RichText::new(text.master_password_task_failed)
                                    .color(theme::palette(ui).error),
                            );
                        }
                        ui.add_space(UI_LAYOUT_GAP);
                        ui.horizontal(|ui| {
                            if theme::primary_button(ui, text.master_password_decrypt).clicked() {
                                start_decryption = true;
                            }
                            if theme::secondary_button(ui, text.master_password_close).clicked() {
                                close_password_window = true;
                            }
                        });
                    }
                });
            if close_password_window {
                password_window_open = false;
            }
        }
        if self.master_password_loading {
            password_window_open = true;
        }
        self.master_password_open = password_window_open;
        if !self.master_password_open {
            self.master_password_input.zeroize();
            self.master_password_input.clear();
            self.master_password_source = None;
            self.master_password_focus_input = false;
        }
        if start_decryption {
            self.begin_decrypt_protected_configs(language);
        }

        let mut result_open = self.master_password_result.is_some();
        if let Some(result) = self.master_password_result.as_ref() {
            let mut close_result = false;
            egui::Window::new(text.master_password_results)
                .id(ui.scope_id().with(UI_ID_MASTER_PASSWORD_RESULT_WINDOW))
                .default_width(UI_MASTER_PASSWORD_WINDOW_WIDTH)
                .default_pos(context.content_rect().center())
                .pivot(egui::Align2::CENTER_CENTER)
                .collapsible(false)
                .resizable(false)
                .open(&mut result_open)
                .show(&context, |ui| {
                    if result.failed.is_empty() {
                        ui.label(text.master_password_success);
                    } else {
                        if !result.unlocked.is_empty() {
                            ui.label(
                                egui::RichText::new(text.master_password_unlocked)
                                    .color(theme::palette(ui).success),
                            );
                            for config in &result.unlocked {
                                ui.label(format!("• {config}"));
                            }
                            ui.add_space(UI_LAYOUT_GAP / 2.0);
                        }
                        ui.label(
                            egui::RichText::new(text.master_password_failed)
                                .color(theme::palette(ui).error),
                        );
                        for config in &result.failed {
                            ui.label(format!("• {config}"));
                        }
                    }
                    ui.add_space(UI_LAYOUT_GAP);
                    if theme::secondary_button(ui, text.master_password_close).clicked() {
                        close_result = true;
                    }
                });
            if close_result {
                result_open = false;
            }
        }
        if !result_open {
            self.master_password_result = None;
        }

        let mut pending_open = self.pending_output_action.is_some();
        let mut confirm_output = false;
        if let Some(action) = self.pending_output_action {
            let mut cancel_output = false;
            let (title, message) = match action {
                OutputAction::Copy => (text.partial_copy_title, text.partial_copy_message),
                OutputAction::Export => (text.partial_export_title, text.partial_export_message),
            };
            let included = exportable_source_names(&self.sessions, text);
            let skipped = source_display_names(&protected_sources(&self.sessions), text);
            let can_continue = partial_output_can_continue(&included);
            egui::Window::new(title)
                .id(ui.scope_id().with(UI_ID_PARTIAL_EXPORT_WINDOW))
                .default_width(UI_MASTER_PASSWORD_WINDOW_WIDTH + 80.0)
                .default_pos(context.content_rect().center())
                .pivot(egui::Align2::CENTER_CENTER)
                .collapsible(false)
                .resizable(false)
                .open(&mut pending_open)
                .show(&context, |ui| {
                    ui.label(message);
                    ui.add_space(UI_LAYOUT_GAP / 2.0);
                    if can_continue {
                        ui.label(
                            egui::RichText::new(text.partial_included)
                                .color(theme::palette(ui).success),
                        );
                        for config in &included {
                            ui.label(format!("• {config}"));
                        }
                    } else {
                        ui.label(
                            egui::RichText::new(text.partial_none_included)
                                .color(theme::palette(ui).muted),
                        );
                    }
                    ui.add_space(UI_LAYOUT_GAP / 2.0);
                    ui.label(
                        egui::RichText::new(text.partial_skipped).color(theme::palette(ui).muted),
                    );
                    for config in &skipped {
                        ui.label(format!("• {config}"));
                    }
                    ui.add_space(UI_LAYOUT_GAP);
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(can_continue, |ui| {
                            if theme::primary_button(ui, text.continue_label).clicked() {
                                confirm_output = true;
                            }
                        });
                        if theme::secondary_button(ui, text.cancel).clicked() {
                            cancel_output = true;
                        }
                    });
                });
            if cancel_output {
                pending_open = false;
            }
        }
        if confirm_output {
            let action = self.pending_output_action.take();
            if let Some(action) = action {
                self.perform_output(action, &context, language);
            }
        } else if !pending_open {
            self.pending_output_action = None;
        }

        self.show_recovery_window(
            &context,
            ui.scope_id().with(UI_ID_RECOVERY_WINDOW),
            text,
            language,
        );
    }
}

fn replace_sessions_by_source(existing: &mut Vec<Session>, incoming: Vec<Session>) -> usize {
    let incoming_sources = incoming
        .iter()
        .map(|session| source_identity(&session.source))
        .collect::<HashSet<_>>();
    existing.retain(|session| !incoming_sources.contains(&source_identity(&session.source)));
    let imported_count = incoming.len();
    existing.extend(incoming);
    imported_count
}

fn reconcile_recovery_state(
    checkpoint: &mut RecoveryCheckpoint,
    runtime: &mut HashMap<String, RecoveryRuntimeState>,
    sessions: &[Session],
    sources: &HashSet<String>,
) {
    for source in sources {
        let has_encrypted_password = sessions
            .iter()
            .any(|session| session.source == *source && session.encrypted_password.is_some());
        if !has_encrypted_password {
            checkpoint.clear_source(source);
            runtime.remove(source);
            continue;
        }

        let fingerprint = source_fingerprint(source, sessions);
        if checkpoint
            .sources
            .get(source)
            .is_some_and(|state| state.fingerprint != fingerprint)
        {
            checkpoint.clear_source(source);
        }
        if runtime
            .get(source)
            .is_some_and(|state| state.fingerprint != fingerprint)
        {
            runtime.remove(source);
        }
    }
}

fn remove_sessions_by_source(sessions: &mut Vec<Session>, source: &str) -> usize {
    let previous_count = sessions.len();
    sessions.retain(|session| session.source != source);
    previous_count - sessions.len()
}

fn source_identity(source: &str) -> String {
    if source.starts_with("HKCU\\") {
        return source.to_lowercase();
    }

    let path = Path::new(source);
    let normalized = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\");
    #[cfg(windows)]
    return normalized.to_lowercase();
    #[cfg(not(windows))]
    normalized
}

fn protected_sources_for_scope(sessions: &[Session], source_scope: Option<&str>) -> Vec<String> {
    let sources = protected_sources(sessions);
    match source_scope {
        Some(source) => sources
            .into_iter()
            .filter(|protected_source| protected_source == source)
            .collect(),
        None => sources,
    }
}

fn source_display_name(source: &str, text: &Labels) -> String {
    if source.starts_with("HKCU\\") {
        return text.source_group_registry.to_owned();
    }

    let file_name = source.rsplit(['\\', '/']).next().unwrap_or(source);
    Path::new(file_name)
        .file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(file_name)
        .to_owned()
}

fn filter_exportable_sessions(sessions: &[Session]) -> Vec<Session> {
    let locked_sources = protected_sources(sessions)
        .into_iter()
        .collect::<HashSet<_>>();
    sessions
        .iter()
        .filter(|session| !locked_sources.contains(&session.source))
        .cloned()
        .collect()
}

fn partial_output_can_continue(included_sources: &[String]) -> bool {
    !included_sources.is_empty()
}

fn should_submit_master_password(field_lost_focus: bool, enter_pressed: bool) -> bool {
    field_lost_focus && enter_pressed
}

fn source_display_name_map(sources: &[String], text: &Labels) -> HashMap<String, String> {
    let named_sources = sources
        .iter()
        .map(|source| (source, source_display_name(source, text)))
        .collect::<Vec<_>>();
    let mut counts = HashMap::<String, usize>::new();
    for (_, name) in &named_sources {
        *counts.entry(name.clone()).or_default() += 1;
    }
    named_sources
        .into_iter()
        .map(|(source, name)| {
            let display = if counts.get(&name).copied().unwrap_or_default() > 1 {
                format!("{name} ({source})")
            } else {
                name
            };
            (source.clone(), display)
        })
        .collect()
}

fn source_display_names(sources: &[String], text: &Labels) -> Vec<String> {
    let mut names = source_display_name_map(sources, text)
        .into_values()
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn exportable_source_names(sessions: &[Session], text: &Labels) -> Vec<String> {
    let locked_sources = protected_sources(sessions)
        .into_iter()
        .collect::<HashSet<_>>();
    let mut exportable_sources = HashSet::<String>::new();
    for session in sessions {
        if !locked_sources.contains(&session.source) {
            exportable_sources.insert(session.source.clone());
        }
    }
    let mut sources = exportable_sources.into_iter().collect::<Vec<_>>();
    sources.sort_unstable();
    source_display_names(&sources, text)
}

fn settings_menu(ui: &mut egui::Ui, app: &mut WinScpApp, text: &Labels, context: &egui::Context) {
    ui.set_min_width(UI_SETTINGS_SWITCH_MENU_MIN_WIDTH);
    let mut action = app.settings.password_click_action;
    ui.menu_button(text.action_on_reveal, |options| {
        options.set_min_width(UI_SETTINGS_SUBMENU_MIN_WIDTH);
        for option in [
            PasswordClickAction::Show,
            PasswordClickAction::Copy,
            PasswordClickAction::ShowAndCopy,
        ] {
            options.selectable_value(&mut action, option, password_action_label(option, text));
        }
    });
    if action != app.settings.password_click_action {
        app.set_password_click_action(action, context);
    }

    let mut preference = app.settings.language;
    ui.menu_button(text.language_label, |options| {
        options.set_min_width(UI_SETTINGS_SUBMENU_MIN_WIDTH);
        for option in [
            LanguagePreference::System,
            LanguagePreference::Russian,
            LanguagePreference::English,
        ] {
            options.selectable_value(
                &mut preference,
                option,
                language_preference_label(option, text),
            );
        }
    });
    if preference != app.settings.language {
        app.set_language(preference, context);
    }

    let mut theme_preference = app.settings.theme;
    ui.menu_button(text.theme_label, |options| {
        options.set_min_width(UI_SETTINGS_SUBMENU_MIN_WIDTH);
        for option in [
            ThemePreference::System,
            ThemePreference::Light,
            ThemePreference::Dark,
        ] {
            options.selectable_value(
                &mut theme_preference,
                option,
                theme_preference_label(option, text),
            );
        }
    });
    if theme_preference != app.settings.theme {
        app.set_theme(theme_preference, context);
    }

    ui.separator();
    let mut exclude_collapsed = app.settings.exclude_collapsed_from_search;
    if theme::switch(ui, &mut exclude_collapsed, text.search_exclude_collapsed).changed() {
        app.set_exclude_collapsed_from_search(exclude_collapsed, context);
    }

    ui.separator();
    if ui.button(text.about).clicked() {
        app.about_open = true;
        ui.close();
    }
}

fn about_window(ui: &mut egui::Ui, text: &Labels) {
    ui.label(
        egui::RichText::new(APP_TITLE)
            .size(UI_SECTION_SIZE)
            .strong()
            .color(theme::palette(ui).text),
    );
    ui.add_space(UI_LAYOUT_GAP / 2.0);

    egui::Grid::new(UI_ID_ABOUT_DETAILS)
        .num_columns(2)
        .spacing(egui::vec2(UI_LAYOUT_GAP, UI_LAYOUT_GAP / 2.0))
        .show(ui, |ui| {
            ui.label(text.about_author);
            ui.label(text.about_author_name);
            ui.end_row();

            ui.label(text.about_version);
            ui.label(APP_VERSION);
            ui.end_row();

            ui.label(text.about_repository);
            ui.hyperlink_to(text.about_open_link, APP_REPOSITORY_URL);
            ui.end_row();

            ui.label(text.about_license);
            ui.hyperlink_to(APP_LICENSE_NAME, APP_LICENSE_URL);
            ui.end_row();
        });
}

fn settings_menu_config() -> egui::containers::menu::MenuConfig {
    egui::containers::menu::MenuConfig::new()
        .submenu_gap(UI_MENU_SUBMENU_GAP)
        .style(|style: &mut egui::Style| {
            egui::menu::menu_style(style);
            style.spacing.item_spacing = egui::vec2(UI_MENU_ITEM_GAP_X, UI_MENU_ITEM_GAP_Y);
            style.spacing.interact_size.y = UI_MENU_ITEM_HEIGHT;
            style.spacing.button_padding =
                egui::vec2(UI_MENU_BUTTON_PADDING_X, UI_MENU_BUTTON_PADDING_Y);
            style.spacing.menu_margin = egui::Margin::same(UI_MENU_MARGIN);
        })
}

fn language_preference_label(preference: LanguagePreference, text: &Labels) -> &'static str {
    match preference {
        LanguagePreference::System => text.language_system,
        LanguagePreference::Russian => text.language_russian,
        LanguagePreference::English => text.language_english,
    }
}

fn theme_preference_label(preference: ThemePreference, text: &Labels) -> &'static str {
    match preference {
        ThemePreference::System => text.theme_system,
        ThemePreference::Light => text.theme_light,
        ThemePreference::Dark => text.theme_dark,
    }
}

fn password_action_label(action: PasswordClickAction, text: &Labels) -> &'static str {
    match action {
        PasswordClickAction::Show => text.action_show,
        PasswordClickAction::Copy => text.action_copy,
        PasswordClickAction::ShowAndCopy => text.action_show_copy,
    }
}

fn should_copy_password(action: PasswordClickAction, currently_visible: bool) -> bool {
    match action {
        PasswordClickAction::Show => false,
        PasswordClickAction::Copy => true,
        PasswordClickAction::ShowAndCopy => !currently_visible,
    }
}

fn toggle_session_visibility(
    reveal_all: &mut bool,
    revealed: &mut HashSet<usize>,
    index: usize,
    session_count: usize,
    currently_visible: bool,
) {
    if currently_visible {
        if *reveal_all {
            *reveal_all = false;
            revealed.extend((0..session_count).filter(|session_index| *session_index != index));
        } else {
            revealed.remove(&index);
        }
    } else {
        revealed.insert(index);
    }
}

fn correct_restored_window(app: &mut WinScpApp, ctx: &egui::Context) {
    let (maximized, size, monitor) = ctx.input(|input| {
        let viewport = input.viewport();
        (
            viewport.maximized.unwrap_or(false),
            viewport.inner_rect.map(|rect| rect.size()),
            viewport.monitor_size,
        )
    });
    let action = restore_window_action(
        app.window_was_maximized,
        maximized,
        size,
        app.restored_window_size,
        monitor,
    );
    match action {
        RestoreWindowAction::None => {}
        RestoreWindowAction::Repaint => ctx.request_repaint(),
        RestoreWindowAction::Resize(size) => {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
            ctx.request_repaint();
        }
    }
    if !maximized && size.is_some_and(|size| window_size_is_usable(size, monitor)) {
        app.restored_window_size = size;
    }
    app.window_was_maximized = maximized;
}

enum RestoreWindowAction {
    None,
    Repaint,
    Resize(egui::Vec2),
}

fn restore_window_action(
    was_maximized: bool,
    maximized: bool,
    size: Option<egui::Vec2>,
    last_good: Option<egui::Vec2>,
    monitor: Option<egui::Vec2>,
) -> RestoreWindowAction {
    let usable = size.is_some_and(|size| window_size_is_usable(size, monitor));
    if maximized || usable {
        return if was_maximized && !maximized {
            RestoreWindowAction::Repaint
        } else {
            RestoreWindowAction::None
        };
    }
    if !was_maximized && last_good.is_none() {
        return RestoreWindowAction::None;
    }
    RestoreWindowAction::Resize(last_good.unwrap_or(egui::vec2(WINDOW_WIDTH, WINDOW_HEIGHT)))
}

fn window_size_is_usable(size: egui::Vec2, monitor: Option<egui::Vec2>) -> bool {
    if size.x + 1.0 < MIN_WINDOW_WIDTH || size.y + 1.0 < MIN_WINDOW_HEIGHT {
        return false;
    }
    if let Some(monitor) = monitor
        && size.x > monitor.x - 32.0
        && size.y > monitor.y - 80.0
    {
        return false;
    }
    true
}

fn export_format_label(format: ExportFormat, text: &Labels) -> &'static str {
    match format {
        ExportFormat::Text => text.format_text,
        ExportFormat::Json => text.format_json,
        ExportFormat::Xml => text.format_xml,
    }
}

fn filter_session_indices(
    sessions: &[Session],
    query: &str,
    exclude_collapsed: bool,
    collapsed_nodes: &HashSet<CollapsibleNodeId>,
) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    sessions
        .iter()
        .enumerate()
        .filter_map(|(index, session)| {
            if exclude_collapsed && session_is_in_collapsed_node(session, collapsed_nodes) {
                return None;
            }
            let port = session.port.to_string();
            let endpoint = session.endpoint();
            let matches = query.is_empty()
                || [
                    session.name.as_str(),
                    session.host.as_str(),
                    session.username.as_str(),
                    session.connection.label(),
                    port.as_str(),
                    endpoint.as_str(),
                ]
                .iter()
                .any(|field| field.to_lowercase().contains(&query));
            matches.then_some(index)
        })
        .collect()
}

fn pick_ini_files(text: &Labels) -> Option<Vec<PathBuf>> {
    rfd::FileDialog::new()
        .set_title(text.file_picker_title)
        .add_filter(
            text.file_filter_label,
            &[crate::config::constants::CONFIG_EXTENSION],
        )
        .pick_files()
}

fn pick_ini_folder(text: &Labels) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title(text.folder_picker_title)
        .pick_folder()
}

fn egui_file_dialog(text: &Labels, format: ExportFormat, filename: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title(text.save_picker_title)
        .add_filter(text.file_filter_label, &[format.extension()])
        .set_file_name(filename)
        .save_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::SecretString;

    fn search_session(name: &str, host: &str, username: &str) -> Session {
        Session {
            name: name.to_owned(),
            host: host.to_owned(),
            port: 22,
            connection: crate::core::model::ConnectionKind::Sftp,
            username: username.to_owned(),
            folder: Vec::new(),
            password: SecretString::default(),
            encrypted_password: None,
            master_password_verifier: None,
            password_status: PasswordStatus::NotStored,
            source: String::new(),
        }
    }

    fn filter(sessions: &[Session], query: &str) -> Vec<usize> {
        filter_session_indices(sessions, query, false, &HashSet::new())
    }

    fn search_session_in_folder(name: &str, source: &str, folder: &[&str]) -> Session {
        let mut session = search_session(name, "", "");
        session.source = source.to_owned();
        session.folder = folder.iter().map(|part| (*part).to_owned()).collect();
        session
    }

    #[test]
    fn reimport_replaces_sessions_from_the_same_file_and_keeps_other_sources() {
        let mut existing = vec![
            search_session_in_folder("Old value", "C:\\configs\\one.ini", &[]),
            search_session_in_folder("Keep this", "C:\\configs\\two.ini", &[]),
        ];
        let incoming = vec![search_session_in_folder(
            "Updated value",
            "C:\\configs\\one.ini",
            &[],
        )];

        let imported_count = replace_sessions_by_source(&mut existing, incoming);

        assert_eq!(imported_count, 1);
        assert_eq!(existing.len(), 2);
        assert_eq!(existing[0].name, "Keep this");
        assert_eq!(existing[1].name, "Updated value");
    }

    #[test]
    fn reimporting_changed_config_clears_its_old_recovered_password() {
        let source = "C:\\configs\\protected.ini".to_owned();
        let mut old_session = search_session("Saved", "host", "user");
        old_session.source.clone_from(&source);
        old_session.encrypted_password = Some(SecretString::new("ciphertext-before".to_owned()));
        old_session.password_status = PasswordStatus::MasterPasswordProtected;
        let old_fingerprint = source_fingerprint(&source, std::slice::from_ref(&old_session));

        let mut checkpoint = RecoveryCheckpoint::default();
        checkpoint.sources.insert(
            source.clone(),
            RecoverySourceState {
                fingerprint: old_fingerprint.clone(),
                found_password: Some(SecretString::new("old-master-password".to_owned())),
                ..RecoverySourceState::default()
            },
        );
        let mut runtime = HashMap::from([(
            source.clone(),
            RecoveryRuntimeState {
                fingerprint: old_fingerprint,
                status: RecoveryStatus::Found,
                current_combination: String::new(),
                current_length: 1,
                attempts: 1,
                elapsed_millis: 2_000,
                attempts_per_second: 0,
            },
        )]);

        let mut imported_session = old_session;
        imported_session.encrypted_password =
            Some(SecretString::new("ciphertext-after".to_owned()));
        let imported_sources = HashSet::from([source.clone()]);
        reconcile_recovery_state(
            &mut checkpoint,
            &mut runtime,
            &[imported_session],
            &imported_sources,
        );

        assert!(!checkpoint.sources.contains_key(&source));
        assert!(!runtime.contains_key(&source));
    }

    #[test]
    fn reimport_replaces_registry_sessions_as_one_source() {
        let registry_source = "HKCU\\Software\\Vendor\\Sessions";
        let mut existing = vec![search_session_in_folder("Old", registry_source, &[])];
        let incoming = vec![search_session_in_folder("New", registry_source, &[])];

        replace_sessions_by_source(&mut existing, incoming);

        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0].name, "New");
    }

    #[test]
    fn removing_a_source_removes_all_its_sessions_regardless_of_password_status() {
        let file_source = "C:\\configs\\saved.ini";
        let registry_source = "HKCU\\Software\\WinSCP\\Sessions";
        let mut plain = search_session("Plain", "plain.example.test", "user");
        plain.source = file_source.to_owned();
        plain.password_status = PasswordStatus::Available;
        plain.password = SecretString::new("secret".to_owned());

        let mut protected = search_session("Protected", "locked.example.test", "user");
        protected.source = file_source.to_owned();
        protected.password_status = PasswordStatus::MasterPasswordProtected;
        protected.encrypted_password = Some(SecretString::new("wrapped".to_owned()));

        let mut from_registry = search_session("Registry", "registry.example.test", "user");
        from_registry.source = registry_source.to_owned();
        let mut from_other_file = search_session("Other", "other.example.test", "user");
        from_other_file.source = "C:\\configs\\other.ini".to_owned();
        let mut sessions = vec![plain, protected, from_registry, from_other_file];

        assert_eq!(remove_sessions_by_source(&mut sessions, file_source), 2);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|session| session.source != file_source));
        assert_eq!(remove_sessions_by_source(&mut sessions, registry_source), 1);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].source, "C:\\configs\\other.ini");
    }

    #[cfg(windows)]
    #[test]
    fn windows_renderer_uses_only_direct3d12() {
        let options = configure_windows_wgpu_backends(eframe::NativeOptions::default());
        let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = options.wgpu_options.wgpu_setup else {
            panic!("default eframe setup should create a wgpu instance");
        };

        assert!(
            !setup
                .instance_descriptor
                .backends
                .contains(eframe::wgpu::Backends::GL)
        );
        assert!(
            setup
                .instance_descriptor
                .backends
                .contains(eframe::wgpu::Backends::DX12)
        );
        assert!(
            !setup
                .instance_descriptor
                .backends
                .contains(eframe::wgpu::Backends::GL)
        );
        assert!(
            !setup
                .instance_descriptor
                .backends
                .contains(eframe::wgpu::Backends::VULKAN)
        );
    }

    #[test]
    fn search_matches_name_host_and_user_case_insensitively_from_one_character() {
        let sessions = [
            search_session("Alpha gateway", "10.0.0.1", "root"),
            search_session("Backup", "db.example.net", "operator"),
            search_session("Deploy", "192.168.0.5", "DeployBot"),
        ];

        assert_eq!(filter(&sessions, "G"), [0]);
        assert_eq!(filter(&sessions, "DB."), [1]);
        assert_eq!(filter(&sessions, "bot"), [2]);
    }

    #[test]
    fn restoring_a_maximized_window_repaints_a_usable_size_and_replaces_a_broken_one() {
        let monitor = Some(egui::vec2(1920.0, 1080.0));
        let normal = egui::vec2(WINDOW_WIDTH, WINDOW_HEIGHT);
        let tiny = egui::vec2(180.0, 40.0);
        let maximized_size = egui::vec2(1900.0, 1040.0);

        assert!(matches!(
            restore_window_action(true, false, Some(normal), Some(normal), monitor),
            RestoreWindowAction::Repaint
        ));
        match restore_window_action(true, false, Some(tiny), Some(normal), monitor) {
            RestoreWindowAction::Resize(size) => assert_eq!(size, normal),
            RestoreWindowAction::None | RestoreWindowAction::Repaint => {
                panic!("a tiny restored window must be resized")
            }
        }
        match restore_window_action(true, false, Some(maximized_size), Some(normal), monitor) {
            RestoreWindowAction::Resize(size) => assert_eq!(size, normal),
            RestoreWindowAction::None | RestoreWindowAction::Repaint => {
                panic!("a still-maximized client size must be restored")
            }
        }
        match restore_window_action(false, false, Some(tiny), Some(normal), monitor) {
            RestoreWindowAction::Resize(size) => assert_eq!(size, normal),
            RestoreWindowAction::None | RestoreWindowAction::Repaint => {
                panic!("a stuck tiny window must return to the last good size")
            }
        }
        assert!(matches!(
            restore_window_action(false, false, Some(tiny), None, monitor),
            RestoreWindowAction::None
        ));
        assert!(window_size_is_usable(normal, monitor));
        assert!(!window_size_is_usable(tiny, monitor));
    }

    #[test]
    fn search_matches_port_and_connection_type() {
        let mut sessions = [
            search_session("Alpha", "10.0.0.1", "root"),
            search_session("Files", "files.example.test", "backup"),
        ];
        sessions[0].connection = crate::core::model::ConnectionKind::Scp;
        sessions[1].port = 2121;
        sessions[1].connection = crate::core::model::ConnectionKind::Ftp;

        assert_eq!(filter(&sessions, "2121"), [1]);
        assert_eq!(filter(&sessions, "ftp"), [1]);
        assert_eq!(filter(&sessions, "scp"), [0]);
        assert_eq!(filter(&sessions, "files.example.test:2121"), [1]);
    }

    #[test]
    fn empty_search_returns_all_sessions_and_unmatched_search_returns_none() {
        let sessions = [
            search_session("Alpha", "10.0.0.1", "root"),
            search_session("Beta", "10.0.0.2", "admin"),
        ];

        assert_eq!(filter(&sessions, "  "), [0, 1]);
        assert!(filter(&sessions, "missing").is_empty());
    }

    #[test]
    fn exclude_collapsed_search_skips_sessions_under_collapsed_sources_and_folders() {
        let sessions = [
            search_session_in_folder("Root match", "one.ini", &[]),
            search_session_in_folder("Folder match", "one.ini", &["Production", "EU"]),
            search_session_in_folder("Other match", "two.ini", &[]),
        ];
        let collapsed = HashSet::from([
            CollapsibleNodeId::Folder {
                source: "one.ini".to_owned(),
                path: "Production".to_owned(),
            },
            CollapsibleNodeId::Source("two.ini".to_owned()),
        ]);

        assert_eq!(
            filter_session_indices(&sessions, "match", true, &collapsed),
            [0]
        );
    }

    #[test]
    fn clear_list_removes_sessions_search_and_cached_tree_state() {
        let mut app = WinScpApp {
            sessions: vec![search_session("Secret", "host", "user")],
            settings: Settings::default(),
            export_format: ExportFormat::Text,
            revealed: HashSet::from([0]),
            reveal_all: true,
            search_query: "secret".to_owned(),
            cached_search_query: Some("secret".to_owned()),
            cached_session_count: 1,
            cached_collapsed_nodes: HashSet::from([CollapsibleNodeId::Source(
                "source.ini".to_owned(),
            )]),
            filtered_indices: vec![0],
            filtered_index_set: HashSet::from([0]),
            source_groups: Vec::new(),
            collapsed_nodes: HashSet::from([CollapsibleNodeId::Source("source.ini".to_owned())]),
            status: String::new(),
            about_open: false,
            master_passwords: HashMap::new(),
            master_password_open: false,
            master_password_source: None,
            master_password_input: String::new(),
            master_password_visible: false,
            master_password_focus_input: false,
            master_password_error: false,
            master_password_loading: false,
            master_password_task_error: false,
            master_password_worker: None,
            master_password_result: None,
            pending_output_action: None,
            recovery_checkpoint: RecoveryCheckpoint::default(),
            recovery_checkpoint_path: PathBuf::new(),
            recovery_checkpoint_error: false,
            recovery_runtime: HashMap::new(),
            recovery_worker: None,
            recovery_paused: false,
            recovery_window_open: false,
            recovery_scope: None,
            restored_window_size: None,
            window_was_maximized: false,
        };

        app.clear_session_list(Language::Russian);

        assert!(app.sessions.is_empty());
        assert!(app.search_query.is_empty());
        assert!(app.revealed.is_empty());
        assert!(!app.reveal_all);
        assert!(app.filtered_indices.is_empty());
        assert!(app.filtered_index_set.is_empty());
        assert!(app.collapsed_nodes.is_empty());
        assert!(app.source_groups.is_empty());
        assert_eq!(app.status, labels(Language::Russian).list_cleared);
    }

    #[test]
    fn export_filter_skips_every_session_from_a_locked_config() {
        let mut locked = search_session("Protected", "secret.example.test", "admin");
        locked.source = "C:\\configs\\locked.ini".to_owned();
        locked.encrypted_password = Some(SecretString::new("wrapped".to_owned()));
        let mut sibling = search_session("No password", "other.example.test", "user");
        sibling.source = locked.source.clone();
        let mut available = search_session("Available", "open.example.test", "reader");
        available.source = "C:\\configs\\open.ini".to_owned();

        let filtered = filter_exportable_sessions(&[locked, sibling, available]);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "Available");
    }

    #[test]
    fn partial_output_requires_at_least_one_included_config() {
        assert!(!partial_output_can_continue(&[]));
        assert!(partial_output_can_continue(&["open.ini".to_owned()]));
    }

    #[test]
    fn master_password_scope_selects_only_the_requested_protected_config() {
        let mut first = search_session("First", "first.example.test", "user");
        first.source = "first.ini".to_owned();
        first.encrypted_password = Some(SecretString::new("first-wrapped".to_owned()));
        let mut second = search_session("Second", "second.example.test", "user");
        second.source = "second.ini".to_owned();
        second.encrypted_password = Some(SecretString::new("second-wrapped".to_owned()));
        let sessions = [first, second];

        assert_eq!(
            protected_sources_for_scope(&sessions, Some("second.ini")),
            ["second.ini"]
        );
        assert_eq!(
            protected_sources_for_scope(&sessions, None),
            ["first.ini", "second.ini"]
        );
        assert!(protected_sources_for_scope(&sessions, Some("missing.ini")).is_empty());
    }

    #[test]
    fn master_password_submits_when_enter_leaves_the_password_field() {
        assert!(should_submit_master_password(true, true));
        assert!(!should_submit_master_password(true, false));
        assert!(!should_submit_master_password(false, true));
    }

    #[test]
    fn master_password_decryption_completes_in_background_and_updates_sessions() {
        let source = "C:\\configs\\protected.ini";
        let mut session = search_session("Protected", "host.example.test", "admin");
        session.source = source.to_owned();
        session.encrypted_password = Some(SecretString::new(
            crate::core::crypto::tests_support::encrypt_test_master_password("secret", "correct"),
        ));
        session.password_status = PasswordStatus::MasterPasswordProtected;

        let mut app = WinScpApp {
            sessions: vec![session],
            settings: Settings::default(),
            export_format: ExportFormat::Text,
            revealed: HashSet::new(),
            reveal_all: false,
            search_query: String::new(),
            cached_search_query: None,
            cached_session_count: usize::MAX,
            cached_collapsed_nodes: HashSet::new(),
            filtered_indices: Vec::new(),
            filtered_index_set: HashSet::new(),
            source_groups: Vec::new(),
            collapsed_nodes: HashSet::new(),
            status: String::new(),
            about_open: false,
            master_passwords: HashMap::new(),
            master_password_open: true,
            master_password_source: None,
            master_password_input: "correct".to_owned(),
            master_password_visible: false,
            master_password_focus_input: false,
            master_password_error: false,
            master_password_loading: false,
            master_password_task_error: false,
            master_password_worker: None,
            master_password_result: None,
            pending_output_action: None,
            recovery_checkpoint: RecoveryCheckpoint::default(),
            recovery_checkpoint_path: PathBuf::new(),
            recovery_checkpoint_error: false,
            recovery_runtime: HashMap::new(),
            recovery_worker: None,
            recovery_paused: false,
            recovery_window_open: false,
            recovery_scope: None,
            restored_window_size: None,
            window_was_maximized: false,
        };
        let context = egui::Context::default();

        app.begin_decrypt_protected_configs(Language::English);

        assert!(app.master_password_loading);
        assert!(app.sessions[0].encrypted_password.is_some());
        for _ in 0..1_000 {
            app.poll_master_password_decryption(&context);
            if !app.master_password_loading {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert!(!app.master_password_loading);
        assert!(!app.master_password_open);
        assert_eq!(app.sessions[0].password.as_str(), "secret");
        assert!(app.sessions[0].encrypted_password.is_none());
        assert_eq!(
            app.master_password_result
                .as_ref()
                .expect("worker should return a result")
                .unlocked,
            ["protected"]
        );
    }

    #[test]
    fn show_and_copy_copies_only_when_the_password_becomes_visible() {
        assert!(should_copy_password(
            PasswordClickAction::ShowAndCopy,
            false
        ));
        assert!(!should_copy_password(
            PasswordClickAction::ShowAndCopy,
            true
        ));
    }

    #[test]
    fn copy_action_copies_without_changing_visibility() {
        assert!(should_copy_password(PasswordClickAction::Copy, false));
        assert!(should_copy_password(PasswordClickAction::Copy, true));
    }

    #[test]
    fn show_action_never_copies() {
        assert!(!should_copy_password(PasswordClickAction::Show, false));
        assert!(!should_copy_password(PasswordClickAction::Show, true));
    }

    #[test]
    fn hiding_one_password_after_reveal_all_keeps_the_others_visible() {
        let mut reveal_all = true;
        let mut revealed = HashSet::new();
        toggle_session_visibility(&mut reveal_all, &mut revealed, 1, 3, true);

        assert!(!reveal_all);
        assert_eq!(revealed, HashSet::from([0, 2]));
    }

    #[cfg(windows)]
    #[test]
    fn recovery_worker_finds_the_password_and_persists_its_progress() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let checkpoint_path = std::env::temp_dir().join(format!(
            "spe-recovery-worker-{}-{unique}.dat",
            std::process::id()
        ));
        let settings = RecoverySearchSettings {
            minimum_length: 1,
            maximum_length: 1,
            digits: true,
            letters: false,
            symbols: false,
        };
        let target = RecoveryTarget {
            source: "C:\\configs\\recovery.ini".to_owned(),
            fingerprint: "test-fingerprint".to_owned(),
            encrypted_passwords: vec![
                crate::core::crypto::tests_support::encrypt_test_master_password(
                    "saved-password",
                    "2",
                ),
            ],
        };
        let (command_sender, command_receiver) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        run_recovery_search(
            vec![target],
            settings,
            RecoveryCheckpoint::default(),
            checkpoint_path.clone(),
            command_receiver,
            event_sender,
        );
        drop(command_sender);

        let mut found = None;
        while let Ok(event) = event_receiver.try_recv() {
            if let RecoveryEvent::Update(update) = event
                && update.status == RecoveryStatus::Found
            {
                found = update.found_password;
                assert_eq!(update.attempts, 3);
            }
        }
        assert_eq!(found.as_ref().map(SecretString::as_str), Some("2"));
        let saved = load_checkpoint(&checkpoint_path).expect("read encrypted progress");
        assert_eq!(
            saved
                .sources
                .get("C:\\configs\\recovery.ini")
                .and_then(|state| state.found_password.as_ref())
                .map(SecretString::as_str),
            Some("2")
        );
        let _ = fs::remove_file(checkpoint_path);
    }
}
