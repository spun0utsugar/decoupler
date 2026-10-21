use crate::ir:: ConfidenceBreakdown;

/// Compute Shannon entropy in bits per byte `[0.0, 8.0]`.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    (entropy * 10000.0).round() / 10000.0
}

/// Evaluate how well a region's entropy fits structured floating-point or tabular records.
/// IEEE-754 coordinate arrays typically exhibit entropy between 2.2 and 6.8 bits/byte.
pub fn score_entropy_for_structure(entropy: f64) -> f64 {
    if entropy < 0.2 {
        0.15 // Nearly all zeros/constant padding
    } else if (2.0..=6.6).contains(&entropy) {
        0.95 // Ideal structured numerical / tabular zone
    } else if entropy > 7.5 {
        0.10 // Compressed or encrypted stream
    } else {
        0.65
    }
}

/// Score a sequence of 2D coordinates for geometric plausibility:
/// - Rejects NaN, Inf, denormal values, or extreme magnitudes (`> 1e9` or `< 1e-6` when non-zero)
/// - Evaluates step-to-step spatial continuity (low variance in step length vs bounding box diagonal)
/// - Checks non-zero bounding box area/span
pub fn score_coordinate_sequence_2d(pts: &[[f64; 2]]) -> (f64, Vec<String>) {
    let mut notes = Vec::new();
    if pts.len() < 2 {
        return (0.0, vec!["Too few points".to_string()]);
    }

    let mut min_x = f64::INFINITY;
    let mut min_y = f64::INFINITY;
    let mut max_x = f64::NEG_INFINITY;
    let mut max_y = f64::NEG_INFINITY;

    for &[x, y] in pts {
        if !x.is_finite() || !y.is_finite() {
            return (0.0, vec!["Contains non-finite IEEE-754 values".to_string()]);
        }
        let ax = x.abs();
        let ay = y.abs();
        if ax > 1.0e9 || ay > 1.0e9 {
            return (0.0, vec!["Coordinate magnitude exceeds 1e9".to_string()]);
        }
        if (ax > 0.0 && ax < 1.0e-7) || (ay > 0.0 && ay < 1.0e-7) {
            return (
                0.0,
                vec!["Contains subnormal/microscopic float noise".to_string()],
            );
        }
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }

    let dx = max_x - min_x;
    let dy = max_y - min_y;
    let diag = (dx * dx + dy * dy).sqrt();
    if diag < 1.0e-5 {
        return (0.0, vec!["Degenerate zero-span bounding box".to_string()]);
    }

    // Check aspect ratio sanity
    let aspect = if dx > 1e-6 && dy > 1e-6 {
        (dx / dy).max(dy / dx)
    } else {
        1.0
    };
    if aspect > 10_000.0 {
        return (
            0.2,
            vec![format!("Extreme aspect ratio ({:.1})", aspect)],
        );
    }

    // Step continuity analysis
    let mut steps = Vec::with_capacity(pts.len() - 1);
    let mut zero_steps = 0usize;
    for w in pts.windows(2) {
        let sx = w[1][0] - w[0][0];
        let sy = w[1][1] - w[0][1];
        let d = (sx * sx + sy * sy).sqrt();
        if d < 1.0e-9 {
            zero_steps += 1;
        }
        steps.push(d);
    }

    if zero_steps * 2 >= pts.len() {
        return (
            0.1,
            vec!["Over 50% duplicate consecutive vertices".to_string()],
        );
    }

    let mean_step = steps.iter().sum::<f64>() / (steps.len() as f64);
    let max_step = steps.iter().copied().fold(0.0_f64, f64::max);
    let ratio = mean_step / diag;

    let mut score: f64 = 0.70;
    if ratio < 0.45 {
        score += 0.15;
        notes.push(format!(
            "Smooth spatial continuity (mean_step/diag = {:.3})",
            ratio
        ));
    }
    if max_step < diag * 0.85 {
        score += 0.10;
        notes.push("No extreme erratic jumps across bounding box".to_string());
    }

    // Check if closed ring
    let first = pts[0];
    let last = pts[pts.len() - 1];
    let close_dist = ((first[0] - last[0]).powi(2) + (first[1] - last[1]).powi(2)).sqrt();
    if pts.len() >= 4 && close_dist <= 1.0e-4 * diag {
        score += 0.05;
        notes.push("Forms closed polygon ring".to_string());
    }

    // Check coordinate domain plausibility (e.g., geographic lon/lat or standard CAD coordinates)
    if min_x >= -180.0 && max_x <= 180.0 && min_y >= -90.0 && max_y <= 90.0 {
        notes.push("Bounds match geographic Lon/Lat domain".to_string());
    } else if min_x >= -1.0e7 && max_x <= 1.0e7 && min_y >= -1.0e7 && max_y <= 1.0e7 {
        notes.push("Bounds match plausible Cartesian/Projected domain".to_string());
    }

    (score.clamp(0.0, 1.0), notes)
}

/// Build a full `ConfidenceBreakdown` for a candidate hypothesis.
pub fn build_confidence(
    internal_consistency: f64,
    pointer_validity: f64,
    region_bytes: &[u8],
    geometric_plausibility: f64,
    mut notes: Vec<String>,
) -> ConfidenceBreakdown {
    let ent = shannon_entropy(region_bytes);
    let ent_score = score_entropy_for_structure(ent);
    notes.push(format!("Region Shannon entropy = {:.3} bits/byte", ent));
    ConfidenceBreakdown::compute(
        internal_consistency,
        pointer_validity,
        ent_score,
        geometric_plausibility,
        notes,
    )
}
