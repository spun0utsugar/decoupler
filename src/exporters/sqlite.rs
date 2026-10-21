use crate::ir::DecoupledDocument;
use rusqlite::{params, Connection, Result};
use std::fs;
use std::path::Path;

/// Exports the complete Intermediate Representation (IR) into a relational SQLite database
/// containing `document_metadata`, `provenance`, `geometries`, `attribute_tables`, `attribute_rows`,
/// `raster_tiles`, and `embedded_assets`.
pub fn export_sqlite(doc: &DecoupledDocument, path: &Path) -> Result<()> {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    let mut conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;

        CREATE TABLE document_metadata (
            source_filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            detected_magic TEXT NOT NULL,
            format_family TEXT NOT NULL,
            overall_entropy REAL NOT NULL,
            crs_type TEXT NOT NULL,
            epsg_hint INTEGER,
            tool_version TEXT NOT NULL
        );

        CREATE TABLE decompressed_streams (
            stream_id TEXT PRIMARY KEY,
            parent_lineage TEXT NOT NULL,
            depth INTEGER NOT NULL,
            codec TEXT NOT NULL,
            host_offset INTEGER NOT NULL,
            compressed_length INTEGER NOT NULL,
            decompressed_length INTEGER NOT NULL,
            expansion_ratio REAL NOT NULL,
            sha256 TEXT NOT NULL
        );

        CREATE TABLE provenance (
            provenance_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            entity_kind TEXT NOT NULL,
            stream_lineage TEXT NOT NULL,
            host_compressed_offset INTEGER,
            host_compressed_length INTEGER,
            byte_offset INTEGER NOT NULL,
            byte_length INTEGER NOT NULL,
            detector TEXT NOT NULL,
            endianness TEXT NOT NULL,
            confidence_composite REAL NOT NULL,
            internal_consistency REAL NOT NULL,
            pointer_validity REAL NOT NULL,
            entropy_score REAL NOT NULL,
            geometric_plausibility REAL NOT NULL,
            notes_json TEXT NOT NULL
        );

        CREATE TABLE geometries (
            feature_id TEXT PRIMARY KEY,
            layer_id TEXT NOT NULL,
            layer_name TEXT NOT NULL,
            geometry_type TEXT NOT NULL,
            vertex_count INTEGER NOT NULL,
            min_x REAL,
            min_y REAL,
            max_x REAL,
            max_y REAL,
            coordinates_json TEXT NOT NULL,
            properties_json TEXT NOT NULL,
            provenance_id TEXT NOT NULL,
            stream_lineage TEXT NOT NULL,
            byte_offset INTEGER NOT NULL,
            confidence REAL NOT NULL
        );

        CREATE TABLE attribute_tables (
            table_id TEXT PRIMARY KEY,
            table_name TEXT NOT NULL,
            record_stride INTEGER NOT NULL,
            record_count INTEGER NOT NULL,
            schema_json TEXT NOT NULL,
            provenance_id TEXT NOT NULL,
            byte_offset INTEGER NOT NULL,
            confidence REAL NOT NULL
        );

        CREATE TABLE attribute_rows (
            table_id TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            row_json TEXT NOT NULL,
            PRIMARY KEY (table_id, row_index)
        );

        CREATE TABLE raster_tiles (
            raster_id TEXT PRIMARY KEY,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            channels INTEGER NOT NULL,
            bit_depth INTEGER NOT NULL,
            format TEXT NOT NULL,
            exported_path TEXT,
            provenance_id TEXT NOT NULL,
            byte_offset INTEGER NOT NULL,
            confidence REAL NOT NULL
        );

        CREATE TABLE embedded_assets (
            asset_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            description TEXT NOT NULL,
            entropy REAL NOT NULL,
            is_opaque INTEGER NOT NULL,
            metadata_json TEXT NOT NULL,
            provenance_id TEXT NOT NULL,
            byte_offset INTEGER NOT NULL,
            byte_length INTEGER NOT NULL,
            confidence REAL NOT NULL
        );
        ",
    )?;

    let tx = conn.transaction()?;

    tx.execute(
        "INSERT INTO document_metadata VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            doc.metadata.source_filename,
            doc.metadata.file_size as i64,
            doc.metadata.sha256,
            doc.metadata.detected_magic,
            doc.metadata.format_family,
            doc.metadata.overall_entropy,
            doc.coordinate_system.crs_type,
            doc.coordinate_system.epsg_hint,
            doc.metadata.tool_version,
        ],
    )?;

    for ds in &doc.decompressed_streams {
        tx.execute(
            "INSERT INTO decompressed_streams VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                ds.stream_id,
                ds.parent_lineage,
                ds.depth as i64,
                ds.codec,
                ds.host_offset as i64,
                ds.compressed_length as i64,
                ds.decompressed_length as i64,
                ds.expansion_ratio,
                ds.sha256,
            ],
        )?;
    }

    for layer in &doc.layers {
        for feat in &layer.features {
            let p = &feat.provenance;
            let notes_json = serde_json::to_string(&p.confidence.notes).unwrap_or_default();
            let (host_off, host_len) = match p.host_compressed_span {
                Some(s) => (Some(s.offset as i64), Some(s.length as i64)),
                None => (None, None),
            };
            tx.execute(
                "INSERT INTO provenance VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    p.id,
                    feat.id,
                    "GEOMETRY",
                    p.stream_lineage,
                    host_off,
                    host_len,
                    p.span.offset as i64,
                    p.span.length as i64,
                    p.detector,
                    p.endianness,
                    p.confidence.composite,
                    p.confidence.internal_consistency,
                    p.confidence.pointer_validity,
                    p.confidence.entropy_score,
                    p.confidence.geometric_plausibility,
                    notes_json,
                ],
            )?;

            let coords_json = serde_json::to_string(&feat.geometry).unwrap_or_default();
            let props_json = serde_json::to_string(&feat.properties).unwrap_or_default();
            let (min_x, min_y, max_x, max_y) = match &feat.bbox {
                Some(b) => (Some(b.min_x), Some(b.min_y), Some(b.max_x), Some(b.max_y)),
                None => (None, None, None, None),
            };

            tx.execute(
                "INSERT INTO geometries VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    feat.id,
                    layer.id,
                    layer.name,
                    feat.geometry.kind_name(),
                    feat.geometry.vertex_count() as i64,
                    min_x,
                    min_y,
                    max_x,
                    max_y,
                    coords_json,
                    props_json,
                    p.id,
                    p.stream_lineage,
                    p.span.offset as i64,
                    p.confidence.composite,
                ],
            )?;
        }
    }

    for tbl in &doc.attribute_tables {
        let p = &tbl.provenance;
        let notes_json = serde_json::to_string(&p.confidence.notes).unwrap_or_default();
        let (host_off, host_len) = match p.host_compressed_span {
            Some(s) => (Some(s.offset as i64), Some(s.length as i64)),
            None => (None, None),
        };
        tx.execute(
            "INSERT INTO provenance VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                p.id,
                tbl.id,
                "ATTRIBUTE_TABLE",
                p.stream_lineage,
                host_off,
                host_len,
                p.span.offset as i64,
                p.span.length as i64,
                p.detector,
                p.endianness,
                p.confidence.composite,
                p.confidence.internal_consistency,
                p.confidence.pointer_validity,
                p.confidence.entropy_score,
                p.confidence.geometric_plausibility,
                notes_json,
            ],
        )?;

        let schema_json = serde_json::to_string(&tbl.columns).unwrap_or_default();
        tx.execute(
            "INSERT INTO attribute_tables VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                tbl.id,
                tbl.name,
                tbl.record_stride as i64,
                tbl.record_count as i64,
                schema_json,
                p.id,
                p.span.offset as i64,
                p.confidence.composite,
            ],
        )?;

        for (r_idx, row) in tbl.rows.iter().enumerate() {
            let row_json = serde_json::to_string(row).unwrap_or_default();
            tx.execute(
                "INSERT INTO attribute_rows VALUES (?1, ?2, ?3)",
                params![tbl.id, r_idx as i64, row_json],
            )?;
        }
    }

    for tile in &doc.raster_tiles {
        let p = &tile.provenance;
        let notes_json = serde_json::to_string(&p.confidence.notes).unwrap_or_default();
        let (host_off, host_len) = match p.host_compressed_span {
            Some(s) => (Some(s.offset as i64), Some(s.length as i64)),
            None => (None, None),
        };
        tx.execute(
            "INSERT INTO provenance VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                p.id,
                tile.id,
                "RASTER_TILE",
                p.stream_lineage,
                host_off,
                host_len,
                p.span.offset as i64,
                p.span.length as i64,
                p.detector,
                p.endianness,
                p.confidence.composite,
                p.confidence.internal_consistency,
                p.confidence.pointer_validity,
                p.confidence.entropy_score,
                p.confidence.geometric_plausibility,
                notes_json,
            ],
        )?;

        tx.execute(
            "INSERT INTO raster_tiles VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                tile.id,
                tile.width as i64,
                tile.height as i64,
                tile.channels as i64,
                tile.bit_depth as i64,
                tile.format,
                tile.exported_path,
                p.id,
                p.span.offset as i64,
                p.confidence.composite,
            ],
        )?;
    }

    for asset in &doc.embedded_assets {
        let p = &asset.provenance;
        let notes_json = serde_json::to_string(&p.confidence.notes).unwrap_or_default();
        let (host_off, host_len) = match p.host_compressed_span {
            Some(s) => (Some(s.offset as i64), Some(s.length as i64)),
            None => (None, None),
        };
        tx.execute(
            "INSERT INTO provenance VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                p.id,
                asset.id,
                "EMBEDDED_ASSET",
                p.stream_lineage,
                host_off,
                host_len,
                p.span.offset as i64,
                p.span.length as i64,
                p.detector,
                p.endianness,
                p.confidence.composite,
                p.confidence.internal_consistency,
                p.confidence.pointer_validity,
                p.confidence.entropy_score,
                p.confidence.geometric_plausibility,
                notes_json,
            ],
        )?;

        let meta_json = serde_json::to_string(&asset.metadata).unwrap_or_default();
        tx.execute(
            "INSERT INTO embedded_assets VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                asset.id,
                asset.kind,
                asset.description,
                asset.entropy,
                if asset.is_opaque { 1 } else { 0 },
                meta_json,
                p.id,
                p.span.offset as i64,
                p.span.length as i64,
                p.confidence.composite,
            ],
        )?;
    }

    tx.commit()
}
