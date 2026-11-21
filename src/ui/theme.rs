use eframe::egui;

use crate::config::constants::*;
use crate::core::model::ThemePreference as AppearancePreference;

#[derive(Clone, Copy)]
pub struct Palette {
    pub background: egui::Color32,
    pub surface: egui::Color32,
    pub surface_raised: egui::Color32,
    pub input: egui::Color32,
    pub folder: egui::Color32,
    pub border: egui::Color32,
    pub accent: egui::Color32,
    pub accent_soft: egui::Color32,
    pub accent_text: egui::Color32,
    pub text: egui::Color32,
    pub muted: egui::Color32,
    pub success: egui::Color32,
    pub error: egui::Color32,
}

impl Palette {
    fn dark() -> Self {
        Self {
            background: color(UI_COLOR_BACKGROUND),
            surface: color(UI_COLOR_SURFACE),
            surface_raised: color(UI_COLOR_SURFACE_RAISED),
            input: color(UI_COLOR_INPUT),
            folder: color(UI_COLOR_FOLDER),
            border: color(UI_COLOR_BORDER),
            accent: color(UI_COLOR_ACCENT),
            accent_soft: color(UI_COLOR_ACCENT_SOFT),
            accent_text: color(UI_COLOR_TEXT),
            text: color(UI_COLOR_TEXT),
            muted: color(UI_COLOR_MUTED),
            success: color(UI_COLOR_SUCCESS),
            error: color(UI_COLOR_ERROR),
        }
    }

    fn light() -> Self {
        Self {
            background: color(UI_LIGHT_COLOR_BACKGROUND),
            surface: color(UI_LIGHT_COLOR_SURFACE),
            surface_raised: color(UI_LIGHT_COLOR_SURFACE_RAISED),
            input: color(UI_LIGHT_COLOR_INPUT),
            folder: color(UI_LIGHT_COLOR_FOLDER),
            border: color(UI_LIGHT_COLOR_BORDER),
            accent: color(UI_LIGHT_COLOR_ACCENT),
            accent_soft: color(UI_LIGHT_COLOR_ACCENT_SOFT),
            accent_text: egui::Color32::WHITE,
            text: color(UI_LIGHT_COLOR_TEXT),
            muted: color(UI_LIGHT_COLOR_MUTED),
            success: color(UI_LIGHT_COLOR_SUCCESS),
            error: color(UI_LIGHT_COLOR_ERROR),
        }
    }
}

pub fn configure(context: &egui::Context) {
    configure_style(context, egui::Theme::Dark, Palette::dark());
    configure_style(context, egui::Theme::Light, Palette::light());
}

pub fn apply_preference(context: &egui::Context, preference: AppearancePreference) {
    let egui_preference = match preference {
        AppearancePreference::System => egui::ThemePreference::System,
        AppearancePreference::Light => egui::ThemePreference::Light,
        AppearancePreference::Dark => egui::ThemePreference::Dark,
    };
    context.set_theme(egui_preference);
}

pub fn palette(ui: &egui::Ui) -> Palette {
    if ui.visuals().dark_mode {
        Palette::dark()
    } else {
        Palette::light()
    }
}

fn configure_style(context: &egui::Context, theme: egui::Theme, palette: Palette) {
    context.style_mut_of(theme, |style| {
        style.spacing.item_spacing = egui::vec2(UI_LAYOUT_GAP, UI_ROW_GAP);
        style.spacing.window_margin = egui::Margin::same(UI_CARD_PADDING);
        style.spacing.button_padding = egui::vec2(UI_LAYOUT_GAP, UI_COMPACT_PADDING as f32);
        style.spacing.interact_size.y = UI_BUTTON_HEIGHT;

        let visuals = &mut style.visuals;
        visuals.dark_mode = theme == egui::Theme::Dark;
        visuals.panel_fill = palette.background;
        visuals.window_fill = palette.surface;
        visuals.window_corner_radius = egui::CornerRadius::same(UI_CARD_RADIUS);
        visuals.menu_corner_radius = egui::CornerRadius::same(UI_CONTROL_RADIUS);
        visuals.faint_bg_color = palette.surface_raised;
        visuals.extreme_bg_color = palette.input;
        visuals.text_edit_bg_color = Some(palette.input);
        visuals.override_text_color = Some(palette.text);
        visuals.weak_text_color = Some(palette.muted);
        visuals.hyperlink_color = palette.accent;
        visuals.selection.bg_fill = palette.accent_soft;
        visuals.selection.stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.text);
        visuals.button_frame = true;
        visuals.collapsing_header_frame = false;

        visuals.widgets.noninteractive.bg_fill = palette.background;
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.text);
        visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(UI_BORDER_WIDTH, palette.border);

        visuals.widgets.inactive.bg_fill = palette.surface_raised;
        visuals.widgets.inactive.weak_bg_fill = palette.surface_raised;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.border);
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.text);
        visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(UI_CONTROL_RADIUS);

        visuals.widgets.hovered.bg_fill = palette.accent_soft;
        visuals.widgets.hovered.weak_bg_fill = palette.accent_soft;
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.accent);
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.text);
        visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(UI_CONTROL_RADIUS);

        visuals.widgets.active.bg_fill = palette.accent;
        visuals.widgets.active.weak_bg_fill = palette.accent;
        visuals.widgets.active.bg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.accent);
        visuals.widgets.active.fg_stroke = egui::Stroke::new(UI_BORDER_WIDTH, palette.accent_text);
        visuals.widgets.active.corner_radius = egui::CornerRadius::same(UI_CONTROL_RADIUS);

        visuals.widgets.open = visuals.widgets.hovered;
    });
}

fn color(rgb: [u8; 3]) -> egui::Color32 {
    egui::Color32::from_rgb(rgb[0], rgb[1], rgb[2])
}

pub fn chrome_panel_frame(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(6, 3))
        .fill(palette(ui).background)
}

pub fn list_row_frame(ui: &egui::Ui, muted: bool) -> egui::Frame {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(if muted {
            palette.background
        } else {
            palette.surface
        })
        .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
        .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
        .inner_margin(egui::Margin::symmetric(8, 3))
}

pub fn card_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(palette.surface)
        .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
        .corner_radius(egui::CornerRadius::same(UI_CARD_RADIUS))
        .inner_margin(egui::Margin::same(UI_CARD_PADDING))
}

pub fn folder_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(palette.folder)
        .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
        .corner_radius(egui::CornerRadius::same(UI_CARD_RADIUS))
        .inner_margin(egui::Margin::same(UI_COMPACT_PADDING))
}

pub fn subdued_folder_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(palette.background)
        .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
        .corner_radius(egui::CornerRadius::same(UI_CARD_RADIUS))
        .inner_margin(egui::Margin::same(UI_COMPACT_PADDING))
}

pub fn password_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(palette.input)
        .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
        .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
        .inner_margin(egui::Margin::same(UI_COMPACT_PADDING))
}

pub fn subdued_password_frame(ui: &egui::Ui) -> egui::Frame {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(palette.background)
        .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
        .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
        .inner_margin(egui::Margin::same(UI_COMPACT_PADDING))
}

pub fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let palette = palette(ui);
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .strong()
                .color(palette.accent_text),
        )
        .fill(palette.accent)
        .stroke(egui::Stroke::NONE)
        .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
        .min_size(egui::vec2(0.0, UI_BUTTON_HEIGHT)),
    )
}

pub fn secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(label)
            .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
            .min_size(egui::vec2(0.0, UI_BUTTON_HEIGHT)),
    )
}

pub fn secondary_button_sized(ui: &mut egui::Ui, label: &str, size: egui::Vec2) -> egui::Response {
    ui.add(
        egui::Button::new(label)
            .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
            .min_size(size),
    )
}

pub fn subdued_secondary_button_sized(
    ui: &mut egui::Ui,
    label: &str,
    size: egui::Vec2,
) -> egui::Response {
    let palette = palette(ui);
    ui.add(
        egui::Button::new(egui::RichText::new(label).color(palette.muted))
            .fill(palette.background)
            .stroke(egui::Stroke::new(UI_BORDER_WIDTH, palette.border))
            .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
            .min_size(size),
    )
}

pub fn switch(ui: &mut egui::Ui, value: &mut bool, label: &str) -> egui::Response {
    let (rect, mut response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), UI_MENU_ITEM_HEIGHT),
        egui::Sense::click(),
    );
    if response.clicked() {
        *value = !*value;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Switch, ui.is_enabled(), *value, label)
    });

    if ui.is_rect_visible(rect) {
        let palette = palette(ui);
        let painter = ui.painter();
        if response.hovered() {
            painter.rect_filled(
                rect,
                egui::CornerRadius::same(UI_CONTROL_RADIUS),
                palette.accent_soft,
            );
        }

        painter.text(
            egui::pos2(rect.left() + UI_SWITCH_LABEL_PADDING, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            egui::FontId::proportional(UI_META_SIZE),
            palette.text,
        );

        let track_rect = egui::Rect::from_center_size(
            egui::pos2(
                rect.right() - UI_SWITCH_LABEL_PADDING - UI_SWITCH_WIDTH / 2.0,
                rect.center().y,
            ),
            egui::vec2(UI_SWITCH_WIDTH, UI_SWITCH_HEIGHT),
        );
        painter.rect_filled(
            track_rect,
            egui::CornerRadius::same((UI_SWITCH_HEIGHT / 2.0) as u8),
            if *value {
                palette.accent
            } else {
                palette.surface_raised
            },
        );
        painter.rect_stroke(
            track_rect,
            egui::CornerRadius::same((UI_SWITCH_HEIGHT / 2.0) as u8),
            egui::Stroke::new(UI_BORDER_WIDTH, palette.border),
            egui::StrokeKind::Inside,
        );

        let knob_offset = UI_SWITCH_WIDTH / 2.0 - UI_SWITCH_HEIGHT / 2.0 + UI_SWITCH_KNOB_PADDING;
        let knob_x = if *value {
            track_rect.center().x + knob_offset
        } else {
            track_rect.center().x - knob_offset
        };
        painter.circle_filled(
            egui::pos2(knob_x, track_rect.center().y),
            UI_SWITCH_HEIGHT / 2.0 - UI_SWITCH_KNOB_PADDING,
            egui::Color32::WHITE,
        );
    }

    response
}

pub fn badge(ui: &mut egui::Ui, label: &str) {
    let palette = palette(ui);
    egui::Frame::new()
        .fill(palette.accent_soft)
        .corner_radius(egui::CornerRadius::same(UI_CONTROL_RADIUS))
        .inner_margin(egui::Margin::same(UI_COMPACT_PADDING))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).strong().color(palette.text));
        });
}

pub fn drop_target_overlay(ui: &egui::Ui, label: &str) {
    let palette = palette(ui);
    let target_rect = ui.max_rect().shrink(UI_DROP_TARGET_MARGIN);
    let painter = ui.ctx().layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        ui.scope_id().with(UI_ID_DROP_TARGET),
    ));
    painter.rect_stroke(
        target_rect,
        egui::CornerRadius::same(UI_DROP_TARGET_RADIUS),
        egui::Stroke::new(UI_DROP_TARGET_STROKE_WIDTH, palette.accent),
        egui::StrokeKind::Inside,
    );

    let label_galley = painter.layout_no_wrap(
        label.to_owned(),
        egui::FontId::proportional(UI_DROP_HINT_SIZE),
        palette.text,
    );
    let label_size = label_galley.size()
        + egui::vec2(UI_DROP_HINT_PADDING_X * 2.0, UI_DROP_HINT_PADDING_Y * 2.0);
    let label_rect = egui::Rect::from_center_size(target_rect.center(), label_size);
    painter.rect_filled(
        label_rect,
        egui::CornerRadius::same(UI_DROP_HINT_RADIUS),
        palette.surface,
    );
    painter.rect_stroke(
        label_rect,
        egui::CornerRadius::same(UI_DROP_HINT_RADIUS),
        egui::Stroke::new(UI_BORDER_WIDTH, palette.accent),
        egui::StrokeKind::Inside,
    );
    painter.galley(
        label_rect.min + egui::vec2(UI_DROP_HINT_PADDING_X, UI_DROP_HINT_PADDING_Y),
        label_galley,
        palette.text,
    );
}
