use std::collections::{BTreeMap, HashSet};

use eframe::egui;

use super::theme;
use crate::config::constants::{
    FOLDER_PATH_SEPARATOR, PASSWORD_MASK, TREE_INDENT, UI_BUTTON_HEIGHT, UI_COLLAPSED_INDICATOR,
    UI_EXPANDED_INDICATOR, UI_GROUP_MASTER_PASSWORD_BUTTON_WIDTH, UI_LIST_SESSION_ROW_HEIGHT,
    UI_LIST_TREE_ROW_HEIGHT, UI_MASTER_PASSWORD_LOCK, UI_META_SIZE, UI_PASSWORD_AREA_WIDTH,
    UI_PASSWORD_CHARS_PER_LINE, UI_PASSWORD_LINE_HEIGHT, UI_RECOVERY_GROUP_BUTTON_WIDTH,
    UI_SECRET_SIZE, UI_SESSION_TITLE_SIZE, UI_SOURCE_REMOVE_BUTTON_WIDTH,
};
use crate::config::localization::{Labels, Language};
use crate::core::grouping::{SessionGroup, group_session_indices};
use crate::core::model::{PasswordClickAction, PasswordStatus, Session};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum CollapsibleNodeId {
    Source(String),
    Folder { source: String, path: String },
}

#[derive(Default)]
pub(super) struct SessionFolderNode {
    name: String,
    path: String,
    folders: BTreeMap<String, SessionFolderNode>,
    sessions: Vec<usize>,
}

impl SessionFolderNode {
    fn from_session_indices(sessions: &[Session], indices: &[usize]) -> Self {
        let mut root = Self::default();
        for &index in indices {
            let Some(session) = sessions.get(index) else {
                continue;
            };
            let mut current = &mut root;
            for folder in &session.folder {
                let path = if current.path.is_empty() {
                    folder.clone()
                } else {
                    format!("{}{FOLDER_PATH_SEPARATOR}{folder}", current.path)
                };
                current = current
                    .folders
                    .entry(folder.clone())
                    .or_insert_with(|| Self {
                        name: folder.clone(),
                        path,
                        ..Self::default()
                    });
            }
            current.sessions.push(index);
        }
        root
    }
}

pub(super) struct SessionGroupView {
    group: SessionGroup,
    tree: SessionFolderNode,
    contains_master_password: bool,
}

pub(super) enum SessionTreeAction {
    Password(usize),
    EnterMasterPassword(String),
    StartRecovery(String),
    RemoveSource(String),
}

pub(super) fn build_session_group_views(
    sessions: &[Session],
    indices: &[usize],
) -> Vec<SessionGroupView> {
    group_session_indices(sessions, indices)
        .into_iter()
        .map(|group| {
            let contains_master_password = group.session_indices.iter().any(|&index| {
                sessions
                    .get(index)
                    .is_some_and(|session| session.encrypted_password.is_some())
            });
            SessionGroupView {
                tree: SessionFolderNode::from_session_indices(sessions, &group.session_indices),
                group,
                contains_master_password,
            }
        })
        .collect()
}

pub(super) fn session_is_in_collapsed_node(
    session: &Session,
    collapsed_nodes: &HashSet<CollapsibleNodeId>,
) -> bool {
    if collapsed_nodes.contains(&CollapsibleNodeId::Source(session.source.clone())) {
        return true;
    }

    let mut path = String::new();
    session.folder.iter().any(|folder| {
        if path.is_empty() {
            path.clone_from(folder);
        } else {
            path.push_str(FOLDER_PATH_SEPARATOR);
            path.push_str(folder);
        }
        collapsed_nodes.contains(&CollapsibleNodeId::Folder {
            source: session.source.clone(),
            path: path.clone(),
        })
    })
}

enum VisibleRow {
    SourceGroup {
        group_index: usize,
        expanded: bool,
    },
    Folder {
        group_index: usize,
        name: String,
        path: String,
        depth: usize,
        expanded: bool,
    },
    Session {
        index: usize,
        depth: usize,
    },
}

impl VisibleRow {
    fn height(
        &self,
        sessions: &[Session],
        revealed: &HashSet<usize>,
        reveal_all: bool,
        text: &Labels,
    ) -> f32 {
        match self {
            Self::SourceGroup { .. } | Self::Folder { .. } => UI_LIST_TREE_ROW_HEIGHT,
            Self::Session { index, .. } => {
                sessions
                    .get(*index)
                    .map_or(UI_LIST_SESSION_ROW_HEIGHT, |session| {
                        let visible = reveal_all || revealed.contains(index);
                        let password = match session.password_status {
                            PasswordStatus::Available if visible => session.password.as_str(),
                            PasswordStatus::Available => PASSWORD_MASK,
                            PasswordStatus::NotStored => text.password_not_stored,
                            PasswordStatus::MasterPasswordProtected => text.password_protected,
                            PasswordStatus::CouldNotDecrypt => text.password_unavailable,
                        };
                        let lines = password.len().div_ceil(UI_PASSWORD_CHARS_PER_LINE).max(1);
                        UI_LIST_SESSION_ROW_HEIGHT
                            + lines.saturating_sub(1) as f32 * UI_PASSWORD_LINE_HEIGHT
                    })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_session_groups(
    ui: &mut egui::Ui,
    groups: &[SessionGroupView],
    sessions: &[Session],
    matching_indices: &HashSet<usize>,
    search_active: bool,
    exclude_collapsed: bool,
    revealed: &HashSet<usize>,
    reveal_all: bool,
    action: PasswordClickAction,
    text: &Labels,
    language: Language,
    collapsed_nodes: &mut HashSet<CollapsibleNodeId>,
    actions: &mut Vec<SessionTreeAction>,
) -> bool {
    let rows = visible_rows(
        groups,
        collapsed_nodes,
        matching_indices,
        search_active,
        exclude_collapsed,
    );
    if rows.is_empty() {
        return false;
    }

    let row_spacing = ui.spacing().item_spacing.y;
    let content_height = rows
        .iter()
        .map(|row| row.height(sessions, revealed, reveal_all, text))
        .sum::<f32>()
        + row_spacing * rows.len().saturating_sub(1) as f32;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_viewport(ui, |ui, viewport| {
            let content_rect = ui.max_rect();
            let content_top = content_rect.top();
            let content_left = content_rect.left();
            let content_width = ui.available_width();
            ui.set_height(content_height);

            let mut row_top = 0.0;
            for (row_index, row) in rows.iter().enumerate() {
                let row_height = row.height(sessions, revealed, reveal_all, text);
                let row_bottom = row_top + row_height;
                if row_bottom < viewport.min.y {
                    row_top += row_height + row_spacing;
                    continue;
                }
                if row_top > viewport.max.y {
                    break;
                }

                let row_rect = egui::Rect::from_min_size(
                    egui::pos2(content_left, content_top + row_top),
                    egui::vec2(content_width, row_height),
                );
                if ui.is_rect_visible(row_rect) {
                    let mut row_ui =
                        ui.new_child(egui::UiBuilder::new().id_salt(row_index).max_rect(row_rect));
                    render_visible_row(
                        &mut row_ui,
                        row,
                        groups,
                        sessions,
                        revealed,
                        reveal_all,
                        action,
                        text,
                        language,
                        collapsed_nodes,
                        actions,
                    );
                }
                row_top += row_height + row_spacing;
            }
        });
    true
}

fn visible_rows(
    groups: &[SessionGroupView],
    collapsed_nodes: &HashSet<CollapsibleNodeId>,
    matching_indices: &HashSet<usize>,
    search_active: bool,
    exclude_collapsed: bool,
) -> Vec<VisibleRow> {
    let mut rows = Vec::new();
    for (group_index, view) in groups.iter().enumerate() {
        let group_id = CollapsibleNodeId::Source(view.group.source.clone());
        let expanded = !collapsed_nodes.contains(&group_id);
        let has_match = view
            .group
            .session_indices
            .iter()
            .any(|index| matching_indices.contains(index));
        let has_collapsed_descendant =
            group_has_collapsed_node(&view.tree, &view.group.source, collapsed_nodes);
        if search_active && !has_match && !(exclude_collapsed && has_collapsed_descendant) {
            continue;
        }
        rows.push(VisibleRow::SourceGroup {
            group_index,
            expanded,
        });
        if expanded {
            rows.extend(view.tree.sessions.iter().filter_map(|&index| {
                (!search_active || matching_indices.contains(&index))
                    .then_some(VisibleRow::Session { index, depth: 1 })
            }));
            for folder in view.tree.folders.values() {
                append_folder_rows(
                    &mut rows,
                    folder,
                    group_index,
                    &view.group.source,
                    1,
                    collapsed_nodes,
                    matching_indices,
                    search_active,
                    exclude_collapsed,
                );
            }
        }
    }
    rows
}

#[allow(clippy::too_many_arguments)]
fn append_folder_rows(
    rows: &mut Vec<VisibleRow>,
    folder: &SessionFolderNode,
    group_index: usize,
    source: &str,
    depth: usize,
    collapsed_nodes: &HashSet<CollapsibleNodeId>,
    matching_indices: &HashSet<usize>,
    search_active: bool,
    exclude_collapsed: bool,
) {
    let folder_id = CollapsibleNodeId::Folder {
        source: source.to_owned(),
        path: folder.path.clone(),
    };
    let expanded = !collapsed_nodes.contains(&folder_id);
    let has_match = folder_has_matching_session(folder, matching_indices);
    let has_collapsed_descendant = folder_has_collapsed_node(folder, source, collapsed_nodes);
    if search_active && !has_match && !(exclude_collapsed && has_collapsed_descendant) {
        return;
    }
    rows.push(VisibleRow::Folder {
        group_index,
        name: folder.name.clone(),
        path: folder.path.clone(),
        depth,
        expanded,
    });
    if !expanded {
        return;
    }

    rows.extend(folder.sessions.iter().filter_map(|&index| {
        (!search_active || matching_indices.contains(&index)).then_some(VisibleRow::Session {
            index,
            depth: depth + 1,
        })
    }));
    for child in folder.folders.values() {
        append_folder_rows(
            rows,
            child,
            group_index,
            source,
            depth + 1,
            collapsed_nodes,
            matching_indices,
            search_active,
            exclude_collapsed,
        );
    }
}

fn folder_has_matching_session(
    folder: &SessionFolderNode,
    matching_indices: &HashSet<usize>,
) -> bool {
    folder
        .sessions
        .iter()
        .any(|index| matching_indices.contains(index))
        || folder
            .folders
            .values()
            .any(|child| folder_has_matching_session(child, matching_indices))
}

fn folder_has_collapsed_node(
    folder: &SessionFolderNode,
    source: &str,
    collapsed_nodes: &HashSet<CollapsibleNodeId>,
) -> bool {
    collapsed_nodes.contains(&CollapsibleNodeId::Folder {
        source: source.to_owned(),
        path: folder.path.clone(),
    }) || folder
        .folders
        .values()
        .any(|child| folder_has_collapsed_node(child, source, collapsed_nodes))
}

fn group_has_collapsed_node(
    tree: &SessionFolderNode,
    source: &str,
    collapsed_nodes: &HashSet<CollapsibleNodeId>,
) -> bool {
    collapsed_nodes.contains(&CollapsibleNodeId::Source(source.to_owned()))
        || tree
            .folders
            .values()
            .any(|folder| folder_has_collapsed_node(folder, source, collapsed_nodes))
}

#[allow(clippy::too_many_arguments)]
fn render_visible_row(
    ui: &mut egui::Ui,
    row: &VisibleRow,
    groups: &[SessionGroupView],
    sessions: &[Session],
    revealed: &HashSet<usize>,
    reveal_all: bool,
    action: PasswordClickAction,
    text: &Labels,
    language: Language,
    collapsed_nodes: &mut HashSet<CollapsibleNodeId>,
    actions: &mut Vec<SessionTreeAction>,
) {
    match row {
        VisibleRow::SourceGroup {
            group_index,
            expanded,
        } => {
            let group = &groups[*group_index].group;
            let contains_master_password = groups[*group_index].contains_master_password;
            let node_id = CollapsibleNodeId::Source(group.source.clone());
            if render_tree_header(
                ui,
                &group.localized_name(language),
                0,
                *expanded,
                contains_master_password,
                contains_master_password,
                Some(if contains_master_password {
                    text.master_password_group_hint
                } else {
                    &group.source
                }),
                contains_master_password.then_some(group.source.as_str()),
                Some(&group.source),
                text,
                actions,
            ) {
                toggle_collapsible_node(node_id, *expanded, collapsed_nodes);
            }
        }
        VisibleRow::Folder {
            group_index,
            name,
            path,
            depth,
            expanded,
        } => {
            let source = &groups[*group_index].group.source;
            let node_id = CollapsibleNodeId::Folder {
                source: source.clone(),
                path: path.clone(),
            };
            let contains_master_password = groups[*group_index].contains_master_password;
            if render_tree_header(
                ui,
                name,
                *depth,
                *expanded,
                contains_master_password,
                false,
                None,
                None,
                None,
                text,
                actions,
            ) {
                toggle_collapsible_node(node_id, *expanded, collapsed_nodes);
            }
        }
        VisibleRow::Session { index, depth } => {
            if let Some(session) = sessions.get(*index)
                && render_session_row(
                    ui,
                    session,
                    *index,
                    *depth,
                    groups.iter().any(|group| {
                        group.group.source == session.source && group.contains_master_password
                    }),
                    revealed,
                    reveal_all,
                    action,
                    text,
                )
            {
                actions.push(SessionTreeAction::Password(*index));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_tree_header(
    ui: &mut egui::Ui,
    title: &str,
    depth: usize,
    expanded: bool,
    muted: bool,
    contains_master_password: bool,
    tooltip: Option<&str>,
    master_password_source: Option<&str>,
    remove_source: Option<&str>,
    text: &Labels,
    actions: &mut Vec<SessionTreeAction>,
) -> bool {
    let palette = theme::palette(ui);
    let mut clicked = false;
    let frame = if muted {
        theme::subdued_folder_frame(ui)
    } else {
        theme::folder_frame(ui)
    };
    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.add_space(depth as f32 * TREE_INDENT);
            let indicator = if expanded {
                UI_EXPANDED_INDICATOR
            } else {
                UI_COLLAPSED_INDICATOR
            };
            let lock = if contains_master_password {
                format!("  {UI_MASTER_PASSWORD_LOCK}")
            } else {
                String::new()
            };
            let label = format!("{indicator}  {title}{lock}");
            let action_area = master_password_source
                .map_or(0.0, |_| UI_GROUP_MASTER_PASSWORD_BUTTON_WIDTH)
                + master_password_source.map_or(0.0, |_| UI_RECOVERY_GROUP_BUTTON_WIDTH)
                + remove_source.map_or(0.0, |_| UI_SOURCE_REMOVE_BUTTON_WIDTH)
                + ui.spacing().item_spacing.x
                    * (usize::from(master_password_source.is_some()) * 2
                        + usize::from(remove_source.is_some())) as f32;
            let response = ui.add_sized(
                [
                    (ui.available_width() - action_area).max(0.0),
                    UI_BUTTON_HEIGHT,
                ],
                egui::Button::new(egui::RichText::new(label).strong().color(if muted {
                    palette.muted
                } else {
                    palette.text
                })),
            );
            clicked = response.clicked();
            if let Some(tooltip) = tooltip {
                let _ = response.on_hover_text(tooltip);
            }
            if let Some(source) = master_password_source
                && theme::secondary_button_sized(
                    ui,
                    text.master_password_button,
                    egui::vec2(UI_GROUP_MASTER_PASSWORD_BUTTON_WIDTH, UI_BUTTON_HEIGHT),
                )
                .clicked()
            {
                actions.push(SessionTreeAction::EnterMasterPassword(source.to_owned()));
            }
            if let Some(source) = master_password_source
                && theme::secondary_button_sized(
                    ui,
                    text.recovery_start,
                    egui::vec2(UI_RECOVERY_GROUP_BUTTON_WIDTH, UI_BUTTON_HEIGHT),
                )
                .clicked()
            {
                actions.push(SessionTreeAction::StartRecovery(source.to_owned()));
            }
            if let Some(source) = remove_source
                && theme::secondary_button_sized(
                    ui,
                    text.source_group_remove,
                    egui::vec2(UI_SOURCE_REMOVE_BUTTON_WIDTH, UI_BUTTON_HEIGHT),
                )
                .clicked()
            {
                actions.push(SessionTreeAction::RemoveSource(source.to_owned()));
            }
        });
    });
    clicked
}

fn toggle_collapsible_node(
    node_id: CollapsibleNodeId,
    expanded: bool,
    collapsed_nodes: &mut HashSet<CollapsibleNodeId>,
) {
    if expanded {
        collapsed_nodes.insert(node_id);
    } else {
        collapsed_nodes.remove(&node_id);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_session_row(
    ui: &mut egui::Ui,
    session: &Session,
    index: usize,
    depth: usize,
    muted: bool,
    revealed: &HashSet<usize>,
    reveal_all: bool,
    action: PasswordClickAction,
    text: &Labels,
) -> bool {
    let visible = reveal_all || revealed.contains(&index);
    let password_text = match session.password_status {
        PasswordStatus::Available if visible => session.password.as_str(),
        PasswordStatus::Available => PASSWORD_MASK,
        PasswordStatus::NotStored => text.password_not_stored,
        PasswordStatus::MasterPasswordProtected => text.password_protected,
        PasswordStatus::CouldNotDecrypt => text.password_unavailable,
    };
    let button_text = match action {
        PasswordClickAction::Show => {
            if visible {
                text.row_hide
            } else {
                text.row_show
            }
        }
        PasswordClickAction::Copy => text.row_copy,
        PasswordClickAction::ShowAndCopy => {
            if visible {
                text.row_hide
            } else {
                text.row_show_copy
            }
        }
    };

    let mut clicked = false;
    let palette = theme::palette(ui);
    let content_color = if muted { palette.muted } else { palette.text };
    ui.horizontal(|ui| {
        ui.add_space(depth as f32 * TREE_INDENT);
        let frame = if muted {
            theme::subdued_card_frame(ui)
        } else {
            theme::card_frame(ui)
        };
        frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&session.name)
                                .size(UI_SESSION_TITLE_SIZE)
                                .strong()
                                .color(content_color),
                        )
                        .truncate(),
                    );
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(text.col_host)
                                .size(UI_META_SIZE)
                                .color(palette.muted),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&session.host)
                                    .size(UI_META_SIZE)
                                    .color(if muted { palette.muted } else { palette.accent }),
                            )
                            .truncate(),
                        );
                        ui.separator();
                        ui.label(
                            egui::RichText::new(text.col_user)
                                .size(UI_META_SIZE)
                                .color(palette.muted),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&session.username)
                                    .size(UI_META_SIZE)
                                    .color(content_color),
                            )
                            .truncate(),
                        );
                    });
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let enabled = session.password_status == PasswordStatus::Available;
                    clicked = ui
                        .add_enabled_ui(enabled, |ui| {
                            if muted {
                                theme::subdued_secondary_button(ui, button_text)
                            } else {
                                theme::secondary_button(ui, button_text)
                            }
                        })
                        .inner
                        .clicked();
                    let password_frame = if muted {
                        theme::subdued_password_frame(ui)
                    } else {
                        theme::password_frame(ui)
                    };
                    password_frame.show(ui, |ui| {
                        ui.set_min_width(UI_PASSWORD_AREA_WIDTH);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(text.col_password)
                                    .size(UI_META_SIZE)
                                    .color(palette.muted),
                            );
                            ui.label(
                                egui::RichText::new(password_text)
                                    .size(UI_SECRET_SIZE)
                                    .monospace()
                                    .color(
                                        if muted
                                            || session.password_status
                                                == PasswordStatus::MasterPasswordProtected
                                        {
                                            palette.muted
                                        } else {
                                            palette.text
                                        },
                                    ),
                            );
                        });
                    });
                });
            });
        });
    });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::SecretString;

    fn sample(name: &str, folder: &[&str]) -> Session {
        Session {
            name: name.to_owned(),
            host: String::new(),
            username: String::new(),
            folder: folder.iter().map(|part| (*part).to_owned()).collect(),
            password: SecretString::default(),
            encrypted_password: None,
            master_password_verifier: None,
            password_status: PasswordStatus::NotStored,
            source: String::new(),
        }
    }

    fn matches_all(sessions: &[Session]) -> HashSet<usize> {
        (0..sessions.len()).collect()
    }

    #[test]
    fn builds_nested_folder_tree_without_flattening_paths() {
        let sessions = [
            sample("Root", &[]),
            sample("Prod", &["Servers", "Europe"]),
            sample("Test", &["Servers", "Europe"]),
            sample("Build", &["Servers", "Build"]),
        ];
        let tree = SessionFolderNode::from_session_indices(&sessions, &[0, 1, 2, 3]);
        assert_eq!(tree.sessions, [0]);
        assert_eq!(tree.folders["Servers"].folders["Europe"].sessions, [1, 2]);
        assert_eq!(tree.folders["Servers"].folders["Build"].sessions, [3]);
        assert_eq!(
            tree.folders["Servers"].folders["Europe"].path,
            "Servers\\Europe"
        );
    }

    #[test]
    fn builds_tree_for_selected_original_session_indices() {
        let sessions = [
            sample("Root", &[]),
            sample("Europe", &["Servers", "Europe"]),
            sample("Build", &["Servers", "Build"]),
        ];
        let tree = SessionFolderNode::from_session_indices(&sessions, &[1]);

        assert!(tree.sessions.is_empty());
        assert_eq!(tree.folders.len(), 1);
        assert_eq!(tree.folders["Servers"].folders.len(), 1);
        assert_eq!(tree.folders["Servers"].folders["Europe"].sessions, [1]);
    }

    #[test]
    fn marks_source_group_when_any_password_uses_master_password_protection() {
        let mut sessions = [sample("Protected", &[]), sample("Regular", &[])];
        sessions[0].source = "protected.ini".to_owned();
        sessions[1].source = "regular.ini".to_owned();
        sessions[0].password_status = PasswordStatus::MasterPasswordProtected;
        sessions[0].encrypted_password = Some(SecretString::new("wrapped ciphertext".to_owned()));

        let groups = build_session_group_views(&sessions, &[0, 1]);

        assert!(groups[0].contains_master_password);
        assert!(!groups[1].contains_master_password);
    }

    #[test]
    fn virtual_rows_skip_children_of_collapsed_groups_and_folders() {
        let sessions = [
            sample("Root", &[]),
            sample("Europe", &["Servers", "Europe"]),
            sample("Build", &["Servers", "Build"]),
        ];
        let groups = build_session_group_views(&sessions, &[0, 1, 2]);

        let all_matches = matches_all(&sessions);
        let expanded_rows = visible_rows(&groups, &HashSet::new(), &all_matches, false, false);
        assert_eq!(expanded_rows.len(), 7);

        let collapsed_group = HashSet::from([CollapsibleNodeId::Source(String::new())]);
        assert_eq!(
            visible_rows(&groups, &collapsed_group, &all_matches, false, false).len(),
            1
        );

        let collapsed_folder = HashSet::from([CollapsibleNodeId::Folder {
            source: String::new(),
            path: "Servers".to_owned(),
        }]);
        assert_eq!(
            visible_rows(&groups, &collapsed_folder, &all_matches, false, false).len(),
            3
        );
    }

    #[test]
    fn search_keeps_collapsed_tree_headers_visible_so_the_user_can_expand_them() {
        let mut sessions = [
            sample("Root", &[]),
            sample("Europe match", &["Servers", "Europe"]),
        ];
        sessions[0].source = "configs.ini".to_owned();
        sessions[1].source = "configs.ini".to_owned();
        let groups = build_session_group_views(&sessions, &[0, 1]);
        let collapsed_folder = HashSet::from([CollapsibleNodeId::Folder {
            source: "configs.ini".to_owned(),
            path: "Servers".to_owned(),
        }]);

        let matching = HashSet::from([0]);
        let rows = visible_rows(&groups, &collapsed_folder, &matching, true, true);

        assert_eq!(rows.len(), 3);
        assert!(matches!(rows[0], VisibleRow::SourceGroup { .. }));
        assert!(matches!(rows[1], VisibleRow::Session { index: 0, .. }));
        assert!(matches!(rows[2], VisibleRow::Folder { .. }));
    }

    #[test]
    fn no_results_still_shows_a_collapsed_group_header_for_expansion() {
        let mut sessions = [sample("Hidden match", &[])];
        sessions[0].source = "configs.ini".to_owned();
        let groups = build_session_group_views(&sessions, &[0]);
        let collapsed = HashSet::from([CollapsibleNodeId::Source("configs.ini".to_owned())]);

        let rows = visible_rows(&groups, &collapsed, &HashSet::new(), true, true);

        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows[0],
            VisibleRow::SourceGroup {
                expanded: false,
                ..
            }
        ));
    }

    #[test]
    fn search_hides_collapsed_branches_when_the_option_is_off() {
        let mut sessions = [
            sample("No match", &["Servers"]),
            sample("Match", &["Other"]),
        ];
        sessions[0].source = "configs.ini".to_owned();
        sessions[1].source = "configs.ini".to_owned();
        let groups = build_session_group_views(&sessions, &[0, 1]);
        let matching = HashSet::from([1]);
        let rows = visible_rows(&groups, &HashSet::new(), &matching, true, false);

        assert_eq!(rows.len(), 3);
        assert!(matches!(rows[0], VisibleRow::SourceGroup { .. }));
        assert!(matches!(rows[1], VisibleRow::Folder { .. }));
        assert!(matches!(rows[2], VisibleRow::Session { index: 1, .. }));
    }
}
