use crate::ir::DecoupledDocument;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Writes the complete Intermediate Representation as pretty-printed JSON.
pub fn export_ir_json(doc: &DecoupledDocument, path: &Path) -> std::io::Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

/// Writes a detailed, human-auditable plain-text archival decoupling report with every discovered
/// structure, byte offset range, confidence score breakdown, and entropy profile.
pub fn export_audit_txt(doc: &DecoupledDocument, path: &Path) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut out = BufWriter::new(file);

    writeln!(
        out,
        "================================================================================"
    )?;
    writeln!(
        out,
        " OPENARCHIVE DECOUPLER — STRUCTURAL BINARY AUDIT REPORT"
    )?;
    writeln!(
        out,
        "================================================================================"
    )?;
    writeln!(out, "Source File      : {}", doc.metadata.source_filename)?;
    writeln!(out, "File Size        : {} bytes", doc.metadata.file_size)?;
    writeln!(out, "SHA-256 Digest   : {}", doc.metadata.sha256)?;
    writeln!(out, "Detected Magic   : {}", doc.metadata.detected_magic)?;
    writeln!(out, "Format Family    : {}", doc.metadata.format_family)?;
    writeln!(
        out,
        "Overall Entropy  : {:.4} bits/byte",
        doc.metadata.overall_entropy
    )?;
    writeln!(out, "Endianness Hint  : {}", doc.metadata.endianness_hint)?;
    writeln!(out, "CRS Hint         : {} ({})", doc.coordinate_system.crs_type, doc.coordinate_system.units)?;
    if let Some(epsg) = doc.coordinate_system.epsg_hint {
        writeln!(out, "EPSG Code Hint   : EPSG:{}", epsg)?;
    }
    if let Some(mat) = doc.coordinate_system.affine_matrix {
        writeln!(
            out,
            "Affine Matrix    : [a={:.6}, b={:.6}, c={:.6}, d={:.6}, tx={:.6}, ty={:.6}]",
            mat[0], mat[1], mat[2], mat[3], mat[4], mat[5]
        )?;
    }
    if let Some(bb) = doc.global_bbox {
        writeln!(
            out,
            "Global BBox      : min=({}, {}), max=({}, {})",
            bb.min_x, bb.min_y, bb.max_x, bb.max_y
        )?;
    }
    writeln!(
        out,
        "Carved Streams   : {} decompressed virtual sub-stream(s)",
        doc.decompressed_streams.len()
    )?;
    for ds in &doc.decompressed_streams {
        writeln!(
            out,
            "  * [{}] codec={} depth={} parent={} host_offset={:#08x} ({} B -> {} B, ratio={:.2}:1)",
            ds.stream_id,
            ds.codec,
            ds.depth,
            ds.parent_lineage,
            ds.host_offset,
            ds.compressed_length,
            ds.decompressed_length,
            ds.expansion_ratio
        )?;
    }
    writeln!(out)?;

    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    writeln!(
        out,
        " 1. RECOVERED VECTOR LAYERS & GEOMETRIC STRUCTURES ({} layers, {} features)",
        doc.layers.len(),
        doc.total_features()
    )?;
    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    for layer in &doc.layers {
        writeln!(
            out,
            "\n[Layer {}] name=\"{}\" features={} stroke={}",
            layer.id,
            layer.name,
            layer.features.len(),
            layer.style_stroke
        )?;
        for feat in &layer.features {
            let p = &feat.provenance;
            writeln!(
                out,
                "  - Feature {:<16} | Kind: {:<14} | Vertices: {:<5} | Bytes: {:#08x}..{:#08x} ({} B) | Confidence: {:.4}",
                feat.id,
                feat.geometry.kind_name(),
                feat.geometry.vertex_count(),
                p.span.offset,
                p.span.end(),
                p.span.length,
                p.confidence.composite
            )?;
            writeln!(
                out,
                "    Detector: {} | Lineage: {} | Breakdown: [consistency={:.2}, ptr={:.2}, entropy={:.2}, geom={:.2}]",
                p.detector,
                p.stream_lineage,
                p.confidence.internal_consistency,
                p.confidence.pointer_validity,
                p.confidence.entropy_score,
                p.confidence.geometric_plausibility
            )?;
            for note in &p.confidence.notes {
                writeln!(out, "    * {}", note)?;
            }
        }
    }
    writeln!(out)?;

    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    writeln!(
        out,
        " 2. RECOVERED ATTRIBUTE TABLES ({} tables)",
        doc.attribute_tables.len()
    )?;
    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    for tbl in &doc.attribute_tables {
        let p = &tbl.provenance;
        writeln!(
            out,
            "\n[Table {}] name=\"{}\" stride={}B rows={} | Bytes: {:#08x}..{:#08x} ({} B) | Confidence: {:.4}",
            tbl.id,
            tbl.name,
            tbl.record_stride,
            tbl.record_count,
            p.span.offset,
            p.span.end(),
            p.span.length,
            p.confidence.composite
        )?;
        for (idx, row) in tbl.rows.iter().take(10).enumerate() {
            writeln!(
                out,
                "  Row {:<3}: {}",
                idx,
                serde_json::to_string(row).unwrap_or_default()
            )?;
        }
    }
    writeln!(out)?;

    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    writeln!(
        out,
        " 3. RECOVERED RASTER TILES ({} tiles)",
        doc.raster_tiles.len()
    )?;
    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    for tile in &doc.raster_tiles {
        let p = &tile.provenance;
        writeln!(
            out,
            "  - Raster {:<16} | {}x{}x{} ({}) | Bytes: {:#08x}..{:#08x} ({} B) | Confidence: {:.4} | Exported: {:?}",
            tile.id,
            tile.width,
            tile.height,
            tile.channels,
            tile.format,
            p.span.offset,
            p.span.end(),
            p.span.length,
            p.confidence.composite,
            tile.exported_path
        )?;
    }
    writeln!(out)?;

    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    writeln!(
        out,
        " 4. EMBEDDED ASSETS, POINTER TABLES & OPAQUE REGIONS ({} blocks)",
        doc.embedded_assets.len()
    )?;
    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    for asset in &doc.embedded_assets {
        let p = &asset.provenance;
        writeln!(
            out,
            "  - Asset {:<18} | Kind: {:<30} | Opaque: {:<5} | Entropy: {:.3} | Bytes: {:#08x}..{:#08x} ({} B) | Confidence: {:.4}",
            asset.id,
            asset.kind,
            asset.is_opaque,
            asset.entropy,
            p.span.offset,
            p.span.end(),
            p.span.length,
            p.confidence.composite
        )?;
        writeln!(out, "    Description: {}", asset.description)?;
    }
    writeln!(out)?;

    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    writeln!(
        out,
        " 5. ENTROPY PROFILE ({} windows)",
        doc.entropy_profile.len()
    )?;
    writeln!(
        out,
        "--------------------------------------------------------------------------------"
    )?;
    for win in &doc.entropy_profile {
        writeln!(
            out,
            "  Bytes {:#08x}..{:#08x} ({:>4} B) | Entropy: {:.4} bits/byte | {}",
            win.offset,
            win.offset + win.length,
            win.length,
            win.shannon_entropy,
            win.classification
        )?;
    }

    out.flush()
}
