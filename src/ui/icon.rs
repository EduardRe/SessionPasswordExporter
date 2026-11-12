const ICON_SIZE: usize = 128;
const DESIGN_SIZE: f32 = 64.0;
const RASTER_SCALE: usize = 2;
const BACKGROUND: [u8; 3] = [13, 23, 42];
const BACKGROUND_GLOW: [u8; 3] = [40, 67, 117];
const BORDER: [u8; 3] = [69, 101, 151];
const EYE: [u8; 3] = [239, 246, 255];
const EYELID: [u8; 3] = [85, 196, 255];
const IRIS_DARK: [u8; 3] = [26, 58, 132];
const IRIS_TOP: [u8; 3] = [54, 220, 214];
const IRIS_BOTTOM: [u8; 3] = [74, 106, 255];
const PUPIL: [u8; 3] = [9, 20, 38];
const BADGE: [u8; 3] = [46, 224, 195];
const EXPORT_ARROW: [u8; 3] = [10, 37, 58];

pub(crate) struct RgbaIcon {
    pub(crate) rgba: Vec<u8>,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

pub(crate) fn app_icon() -> RgbaIcon {
    let mut rgba = Vec::with_capacity(ICON_SIZE * ICON_SIZE * 4);
    let output_scale = ICON_SIZE as f32 / DESIGN_SIZE;

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let mut channels = [0_u32; 4];

            for sample_y in 0..RASTER_SCALE {
                for sample_x in 0..RASTER_SCALE {
                    let point_x =
                        (x as f32 + (sample_x as f32 + 0.5) / RASTER_SCALE as f32) / output_scale;
                    let point_y =
                        (y as f32 + (sample_y as f32 + 0.5) / RASTER_SCALE as f32) / output_scale;
                    let color = sample_color(point_x, point_y);
                    channels[0] += u32::from(color[0]);
                    channels[1] += u32::from(color[1]);
                    channels[2] += u32::from(color[2]);
                    channels[3] += u32::from(color[3]);
                }
            }

            let sample_count = (RASTER_SCALE * RASTER_SCALE) as u32;
            rgba.extend(channels.map(|channel| (channel / sample_count) as u8));
        }
    }

    RgbaIcon {
        rgba,
        width: ICON_SIZE as u32,
        height: ICON_SIZE as u32,
    }
}

fn sample_color(x: f32, y: f32) -> [u8; 4] {
    let background_distance = rounded_square_distance(x, y);
    if background_distance > 0.0 {
        return [0, 0, 0, 0];
    }

    let glow = (1.0 - circle_distance(x, y, 30.0, 29.0) / 39.0).clamp(0.0, 1.0) * 0.48;
    let mut color = if background_distance > -1.15 {
        BORDER
    } else {
        mix(BACKGROUND, BACKGROUND_GLOW, glow)
    };

    if is_sparkle(x, y, 14.0, 16.0, 2.3) || is_sparkle(x, y, 50.0, 16.5, 1.35) {
        color = [126, 220, 255];
    }

    if let Some(edge_distance) = eye_interior_distance(x, y) {
        color = if edge_distance < 1.05 {
            EYELID
        } else {
            mix([205, 226, 252], EYE, ((y - 19.0) / 24.0).clamp(0.0, 1.0))
        };
    }

    color = draw_iris(color, x, y);
    color = draw_export_badge(color, x, y);

    [color[0], color[1], color[2], 255]
}

fn eye_interior_distance(x: f32, y: f32) -> Option<f32> {
    let dx = (x - 30.5).abs() / 22.5;
    if dx >= 1.0 {
        return None;
    }

    let eye_half_height = 10.7 * (1.0 - dx.powf(1.65)).powf(0.7);
    let edge_distance = eye_half_height - (y - 30.5).abs();
    (edge_distance >= 0.0).then_some(edge_distance)
}

fn draw_iris(base: [u8; 3], x: f32, y: f32) -> [u8; 3] {
    let iris_distance = circle_distance(x, y, 30.5, 30.5);
    if iris_distance > 9.25 {
        return base;
    }

    let mut color = IRIS_DARK;
    if iris_distance <= 8.45 {
        color = mix(IRIS_TOP, IRIS_BOTTOM, ((y - 22.05) / 16.9).clamp(0.0, 1.0));

        let angle = (y - 30.5).atan2(x - 30.5);
        let sector = ((angle + std::f32::consts::PI) / std::f32::consts::TAU * 18.0).fract();
        if (3.7..=8.0).contains(&iris_distance) && sector < 0.11 {
            color = mix(color, [198, 250, 255], 0.58);
        }
    }
    if iris_distance <= 5.15 {
        color = IRIS_DARK;
    }

    let keyhole_head = circle_distance(x, y, 30.5, 29.6) <= 2.35;
    let keyhole_stem = (x - 30.5).abs() <= 1.25 && (30.1..=35.5).contains(&y);
    if keyhole_head || keyhole_stem {
        color = PUPIL;
    }

    if circle_distance(x, y, 27.8, 27.5) <= 1.05 || circle_distance(x, y, 33.8, 33.9) <= 0.52 {
        color = EYE;
    }

    color
}

fn draw_export_badge(base: [u8; 3], x: f32, y: f32) -> [u8; 3] {
    let badge_distance = circle_distance(x, y, 49.3, 47.8);
    if badge_distance <= 10.3 {
        let mut color = if badge_distance > 9.0 {
            [9, 24, 45]
        } else {
            mix(BADGE, [92, 247, 207], ((x - 40.3) / 18.0).clamp(0.0, 1.0))
        };

        let arrow_stem = segment_distance(x, y, 49.3, 50.8, 49.3, 43.2) <= 0.95;
        let arrow_left = segment_distance(x, y, 46.3, 46.2, 49.3, 43.2) <= 0.95;
        let arrow_right = segment_distance(x, y, 52.3, 46.2, 49.3, 43.2) <= 0.95;
        let tray_left = segment_distance(x, y, 45.5, 52.3, 46.3, 54.0) <= 0.95;
        let tray_bottom = segment_distance(x, y, 46.3, 54.0, 52.3, 54.0) <= 0.95;
        let tray_right = segment_distance(x, y, 52.3, 54.0, 53.1, 52.3) <= 0.95;
        if arrow_stem || arrow_left || arrow_right || tray_left || tray_bottom || tray_right {
            color = EXPORT_ARROW;
        }
        color
    } else {
        base
    }
}

fn is_sparkle(x: f32, y: f32, center_x: f32, center_y: f32, radius: f32) -> bool {
    let dx = (x - center_x).abs();
    let dy = (y - center_y).abs();
    (dx <= 0.55 && dy <= radius) || (dy <= 0.55 && dx <= radius)
}

fn rounded_square_distance(x: f32, y: f32) -> f32 {
    let qx = (x - 32.0).abs() - 17.0;
    let qy = (y - 32.0).abs() - 17.0;
    qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - 15.0
}

fn circle_distance(x: f32, y: f32, center_x: f32, center_y: f32) -> f32 {
    (x - center_x).hypot(y - center_y)
}

fn segment_distance(x: f32, y: f32, x1: f32, y1: f32, x2: f32, y2: f32) -> f32 {
    let dx = x2 - x1;
    let dy = y2 - y1;
    let length_squared = dx * dx + dy * dy;
    let projection = (((x - x1) * dx + (y - y1) * dy) / length_squared).clamp(0.0, 1.0);
    circle_distance(x, y, x1 + projection * dx, y1 + projection * dy)
}

fn mix(start: [u8; 3], end: [u8; 3], amount: f32) -> [u8; 3] {
    std::array::from_fn(|index| {
        (f32::from(start[index]) + (f32::from(end[index]) - f32::from(start[index])) * amount)
            .round() as u8
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_icon_has_expected_rgba_dimensions_and_transparent_corners() {
        let icon = app_icon();

        assert_eq!(icon.width, ICON_SIZE as u32);
        assert_eq!(icon.height, ICON_SIZE as u32);
        assert_eq!(icon.rgba.len(), ICON_SIZE * ICON_SIZE * 4);
        assert_eq!(pixel_alpha(&icon, 0, 0), 0);
        assert_eq!(pixel_alpha(&icon, ICON_SIZE / 2, ICON_SIZE / 2), 255);
        let badge_pixel = pixel_red_green_blue(&icon, 107, 96);
        assert!(badge_pixel[1] > 180);
        assert!(badge_pixel[1] > badge_pixel[0]);
    }

    fn pixel_alpha(icon: &RgbaIcon, x: usize, y: usize) -> u8 {
        icon.rgba[(y * icon.width as usize + x) * 4 + 3]
    }

    fn pixel_red_green_blue(icon: &RgbaIcon, x: usize, y: usize) -> [u8; 3] {
        let offset = (y * icon.width as usize + x) * 4;
        [
            icon.rgba[offset],
            icon.rgba[offset + 1],
            icon.rgba[offset + 2],
        ]
    }
}
