use crate::carver::{carve_compressed_streams, CarverConfig};
use crate::ir::*;
use crate::scoring::{build_confidence, score_coordinate_sequence_2d, shannon_entropy};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Maximum bytes scanned per stream by heuristic coordinate/record scanners (16 MB cap for speed on 50 MB+ child streams).
pub const MAX_HEURISTIC_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// Configuration parameters for the binary structural scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub min_confidence: f64,
    pub entropy_window_size: usize,
    pub carver: CarverConfig,
    pub verbose: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.60,
            entropy_window_size: 256,
            carver: CarverConfig::default(),
            verbose: false,
        }
    }
}

const LAYER_PALETTE: &[(&str, &str)] = &[
    ("#0284c7", "rgba(2, 132, 199, 0.15)"),
    ("#16a34a", "rgba(22, 163, 74, 0.15)"),
    ("#ea580c", "rgba(234, 88, 12, 0.15)"),
    ("#9333ea", "rgba(147, 51, 234, 0.15)"),
    ("#dc2626", "rgba(220, 38, 38, 0.15)"),
    ("#0d9488", "rgba(13, 148, 136, 0.15)"),
];

/// Tracks claimed byte intervals so generic heuristic passes don't double-claim structured blocks.
struct ClaimTracker {
    claimed: Vec<(usize, usize)>,
}

impl ClaimTracker {
    fn new() -> Self {
        Self {
            claimed: Vec::new(),
        }
    }

    fn is_claimed(&self, offset: usize, length: usize) -> bool {
        let end = offset + length;
        self.claimed.iter().any(|&(s, e)| offset < e && end > s)
    }

    fn claim(&mut self, offset: usize, length: usize) {
        self.claimed.push((offset, offset + length));
    }
}

/// Detect magic signature and format family from the leading bytes.
pub fn identify_magic(data: &[u8]) -> (String, String) {
    if data.len() >= 4 {
        if &data[0..4] == b"OADC" {
            return (
                "OADC (OpenArchive Vector Container)".to_string(),
                "LEGACY_CAD_GIS_CONTAINER".to_string(),
            );
        }
        let code = BigEndian::read_u32(&data[0..4]);
        if code == 9994 && data.len() >= 100 {
            return (
                "0x0000270A (Esri Shapefile Main Header)".to_string(),
                "ESRI_SHAPEFILE".to_string(),
            );
        }
        if &data[0..4] == b"AC10" {
            return (
                "AC10xx (AutoCAD DWG Archive)".to_string(),
                "AUTOCAD_DWG".to_string(),
            );
        }
        if &data[0..2] == b"\x1f\x8b" {
            return (
                "GZIP Compressed Archive (RFC 1952)".to_string(),
                "COMPRESSED_CONTAINER".to_string(),
            );
        }
        if data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x5E || data[1] == 0x9C || data[1] == 0xDA) {
            return (
                "ZLIB Compressed Stream (RFC 1950)".to_string(),
                "COMPRESSED_CONTAINER".to_string(),
            );
        }
        if &data[0..4] == b"II*\0" || &data[0..4] == b"MM\0*" {
            return (
                "TIFF / GeoTIFF / RAW Container".to_string(),
                "TIFF_CONTAINER".to_string(),
            );
        }
        if &data[0..4] == b"\x89PNG" {
            return ("PNG Image".to_string(), "RASTER_IMAGE".to_string());
        }
    }
    let hex_prefix = hex::encode(&data[..data.len().min(8)]);
    (
        format!("UNKNOWN (0x{})", hex_prefix),
        "GENERIC_STRUCTURED_BINARY".to_string(),
    )
}

/// Primary entry point: carves any compressed streams (up to recursion depth 3), then scans
/// both the raw host binary and all valid decompressed child buffers.
pub fn scan_binary(filename: &str, data: &[u8], cfg: &ScanConfig) -> DecoupledDocument {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex::encode(hasher.finalize());

    let (detected_magic, format_family) = identify_magic(data);
    let overall_entropy = shannon_entropy(data);
    let entropy_profile = compute_entropy_profile(data, cfg.entropy_window_size);

    let mut layers: Vec<Layer> = Vec::new();
    let mut attribute_tables: Vec<AttributeTable> = Vec::new();
    let mut raster_tiles: Vec<RasterTile> = Vec::new();
    let mut embedded_assets: Vec<EmbeddedAsset> = Vec::new();
    let mut crs_hint = CoordinateSystemHint {
        crs_type: "LOCAL_CARTESIAN".to_string(),
        epsg_hint: None,
        affine_matrix: None,
        units: "units".to_string(),
        provenance: None,
    };

    // Step 1: Bounded Recursive Stream Carver & Decompressor (Deflate / zlib / gzip, max depth 3, 64MB cap, 200:1 ratio cap)
    let mut carver_cfg = cfg.carver.clone();
    carver_cfg.verbose = cfg.verbose;
    let (carved_streams, root_carved_spans) = carve_compressed_streams(data, &carver_cfg);
    let decompressed_streams: Vec<DecompressedStreamInfo> =
        carved_streams.iter().map(|c| c.info.clone()).collect();

    // Step 2: Scan the host ("root") binary
    let mut host_tracker = ClaimTracker::new();
    for &(s, e) in &root_carved_spans {
        host_tracker.claim(s, e.saturating_sub(s));
    }
    scan_single_stream(
        data,
        "root",
        None,
        &mut host_tracker,
        &mut layers,
        &mut attribute_tables,
        &mut raster_tiles,
        &mut embedded_assets,
        &mut crs_hint,
        true,
        &entropy_profile,
    );

    // Step 3: Pass-Through Pipeline — run coordinate, container, grid, and tabular structure scanners
    // over every valid decompressed child buffer and annotate provenance with exact decompression lineage.
    for carved in &carved_streams {
        let mut child_tracker = ClaimTracker::new();
        let child_entropy = compute_entropy_profile(&carved.data, cfg.entropy_window_size);
        scan_single_stream(
            &carved.data,
            &carved.info.stream_id,
            Some(carved.host_root_span),
            &mut child_tracker,
            &mut layers,
            &mut attribute_tables,
            &mut raster_tiles,
            &mut embedded_assets,
            &mut crs_hint,
            false,
            &child_entropy,
        );
    }

    // Filter everything by `cfg.min_confidence`
    for layer in &mut layers {
        layer
            .features
            .retain(|f| f.provenance.confidence.composite >= cfg.min_confidence);
    }
    layers.retain(|l| !l.features.is_empty());
    attribute_tables.retain(|t| t.provenance.confidence.composite >= cfg.min_confidence);
    raster_tiles.retain(|r| r.provenance.confidence.composite >= cfg.min_confidence);
    embedded_assets.retain(|a| a.is_opaque || a.provenance.confidence.composite >= cfg.min_confidence);

    let mut doc = DecoupledDocument {
        metadata: DocumentMetadata {
            source_filename: filename.to_string(),
            file_size: data.len(),
            sha256,
            detected_magic,
            format_family,
            overall_entropy,
            endianness_hint: "LITTLE_ENDIAN".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        coordinate_system: crs_hint,
        global_bbox: None,
        entropy_profile,
        decompressed_streams,
        layers,
        attribute_tables,
        raster_tiles,
        embedded_assets,
    };
    doc.recompute_global_bbox();
    doc
}

#[allow(clippy::too_many_arguments)]
fn scan_single_stream(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    layers: &mut Vec<Layer>,
    attribute_tables: &mut Vec<AttributeTable>,
    raster_tiles: &mut Vec<RasterTile>,
    embedded_assets: &mut Vec<EmbeddedAsset>,
    crs_hint: &mut CoordinateSystemHint,
    is_root: bool,
    entropy_profile: &[EntropyWindow],
) {
    // 1. Concrete container extractors
    if data.len() >= 4 && &data[0..4] == b"OADC" {
        parse_oadc_container(
            data,
            stream_lineage,
            host_compressed_span,
            tracker,
            layers,
            attribute_tables,
            raster_tiles,
            embedded_assets,
            crs_hint,
        );
    } else if data.len() >= 100 && BigEndian::read_u32(&data[0..4]) == 9994 {
        parse_shapefile_records(
            data,
            stream_lineage,
            host_compressed_span,
            tracker,
            layers,
            crs_hint,
        );
    }

    let scan_slice = &data[..data.len().min(MAX_HEURISTIC_SCAN_BYTES)];

    // 2. Discover pointer / offset tables in unclaimed space
    detect_offset_tables(
        scan_slice,
        stream_lineage,
        host_compressed_span,
        tracker,
        embedded_assets,
    );

    // 3. Discover embedded PNG/TIFF or raw raster tiles
    detect_embedded_rasters(
        scan_slice,
        stream_lineage,
        host_compressed_span,
        tracker,
        raster_tiles,
    );

    // 4. Discover length-prefixed geometry & coordinate sequences (f64 / f32)
    detect_coordinate_sequences(
        scan_slice,
        stream_lineage,
        host_compressed_span,
        tracker,
        layers,
        crs_hint,
    );

    // 5. Discover repeating fixed-stride attribute records
    detect_repeating_records(
        scan_slice,
        stream_lineage,
        host_compressed_span,
        tracker,
        attribute_tables,
    );

    // 6. Report remaining unclaimed high-entropy opaque/encrypted blocks in root binary
    if is_root {
        detect_opaque_regions(
            data,
            stream_lineage,
            host_compressed_span,
            entropy_profile,
            tracker,
            embedded_assets,
        );
    }
}

fn compute_entropy_profile(data: &[u8], window_size: usize) -> Vec<EntropyWindow> {
    let mut profile = Vec::new();
    if data.is_empty() {
        return profile;
    }
    let step = window_size.max(64);
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + step).min(data.len());
        let slice = &data[offset..end];
        let ent = shannon_entropy(slice);
        let classification = if ent >= 7.45 && slice.len() >= 64 {
            "HIGH_COMPRESSED_OR_OPAQUE"
        } else if ent >= 2.0 {
            "MEDIUM_MIXED"
        } else {
            "LOW_STRUCTURED"
        }
        .to_string();
        profile.push(EntropyWindow {
            offset,
            length: end - offset,
            shannon_entropy: ent,
            classification,
        });
        offset += step;
    }
    profile
}

#[allow(clippy::too_many_arguments)]
fn parse_oadc_container(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    layers: &mut Vec<Layer>,
    attribute_tables: &mut Vec<AttributeTable>,
    raster_tiles: &mut Vec<RasterTile>,
    embedded_assets: &mut Vec<EmbeddedAsset>,
    crs_hint: &mut CoordinateSystemHint,
) {
    if data.len() < 16 {
        return;
    }
    let version = LittleEndian::read_u16(&data[4..6]);
    let section_count = LittleEndian::read_u16(&data[6..8]) as usize;
    let dir_offset = LittleEndian::read_u32(&data[8..12]) as usize;

    let dir_bytes = section_count * 16;
    if dir_offset + dir_bytes > data.len() {
        return;
    }
    tracker.claim(0, 16);
    tracker.claim(dir_offset, dir_bytes);

    let mut valid_ptrs = 0usize;
    let mut section_entries = Vec::new();
    for i in 0..section_count {
        let base = dir_offset + i * 16;
        let sec_type = LittleEndian::read_u32(&data[base..base + 4]);
        let sec_off = LittleEndian::read_u32(&data[base + 4..base + 8]) as usize;
        let sec_len = LittleEndian::read_u32(&data[base + 8..base + 12]) as usize;
        let sec_meta = LittleEndian::read_u32(&data[base + 12..base + 16]);
        if sec_off + sec_len <= data.len() && sec_off >= 16 {
            valid_ptrs += 1;
            section_entries.push((i, sec_type, sec_off, sec_len, sec_meta));
        }
    }

    let ptr_validity = if section_count > 0 {
        (valid_ptrs as f64) / (section_count as f64)
    } else {
        0.0
    };

    let mut dir_meta = BTreeMap::new();
    dir_meta.insert(
        "container_version".to_string(),
        AttributeValue::Int(version as i64),
    );
    dir_meta.insert(
        "section_count".to_string(),
        AttributeValue::Int(section_count as i64),
    );
    dir_meta.insert(
        "valid_pointers".to_string(),
        AttributeValue::Int(valid_ptrs as i64),
    );

    embedded_assets.push(EmbeddedAsset {
        id: format!("asset_offset_dir_{}", embedded_assets.len()),
        kind: "OFFSET_TABLE".to_string(),
        description: format!(
            "Validated section pointer directory ({} entries, v{})",
            section_count, version
        ),
        entropy: shannon_entropy(&data[dir_offset..dir_offset + dir_bytes]),
        is_opaque: false,
        metadata: dir_meta,
        provenance: Provenance {
            id: format!("prov_offset_dir_{}", embedded_assets.len()),
            span: ByteSpan::new(dir_offset, dir_bytes),
            detector: "PointerTableValidator".to_string(),
            endianness: "LITTLE_ENDIAN".to_string(),
            stream_lineage: stream_lineage.to_string(),
            host_compressed_span,
            confidence: build_confidence(
                0.98,
                ptr_validity,
                &data[dir_offset..dir_offset + dir_bytes],
                0.95,
                vec![format!(
                    "{}/{} section pointers resolve cleanly within stream bounds",
                    valid_ptrs, section_count
                )],
            ),
        },
    });

    for (idx, sec_type, sec_off, sec_len, sec_meta) in section_entries {
        let is_already_claimed = tracker.is_claimed(sec_off, sec_len);
        let slice = &data[sec_off..sec_off + sec_len];
        tracker.claim(sec_off, sec_len);

        match sec_type {
            1 if sec_len >= 52 => {
                let mut mat = [0.0f64; 6];
                for (i, val) in mat.iter_mut().enumerate() {
                    *val = LittleEndian::read_f64(&slice[i * 8..(i + 1) * 8]);
                }
                let epsg = LittleEndian::read_u32(&slice[48..52]);
                *crs_hint = CoordinateSystemHint {
                    crs_type: if epsg > 0 {
                        "PROJECTED_OR_GEOGRAPHIC_EPSG".to_string()
                    } else {
                        "AFFINE_LOCAL_CAD".to_string()
                    },
                    epsg_hint: if epsg > 0 { Some(epsg) } else { None },
                    affine_matrix: Some(mat),
                    units: if epsg == 4326 {
                        "degrees".to_string()
                    } else {
                        "meters".to_string()
                    },
                    provenance: Some(Provenance {
                        id: format!("prov_crs_{}", idx),
                        span: ByteSpan::new(sec_off, sec_len),
                        detector: "AffineCrsDetector".to_string(),
                        endianness: "LITTLE_ENDIAN".to_string(),
                        stream_lineage: stream_lineage.to_string(),
                        host_compressed_span,
                        confidence: build_confidence(
                            0.96,
                            1.0,
                            slice,
                            0.95,
                            vec![format!("Recovered 2D affine transform & EPSG={}", epsg)],
                        ),
                    }),
                };
            }
            2 if sec_len >= 24 => {
                let name_bytes = &slice[0..16];
                let layer_name = String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .trim()
                    .to_string();
                let layer_name = if layer_name.is_empty() {
                    format!("layer_{}", idx)
                } else {
                    layer_name
                };
                let geom_kind = LittleEndian::read_u16(&slice[16..18]);
                let feat_count = LittleEndian::read_u16(&slice[18..20]) as usize;
                let mut cursor = 24usize;
                let mut features = Vec::new();
                let layer_id = format!("layer_{}_{}", layers.len(), idx);

                for f_idx in 0..feat_count {
                    if cursor + 8 > sec_len {
                        break;
                    }
                    let feat_start = sec_off + cursor;
                    let feat_id_num = LittleEndian::read_u32(&slice[cursor..cursor + 4]);
                    let vtx_count = LittleEndian::read_u32(&slice[cursor + 4..cursor + 8]) as usize;
                    cursor += 8;
                    let byte_needed = vtx_count * 16;
                    if cursor + byte_needed > sec_len || vtx_count == 0 {
                        break;
                    }
                    let mut pts = Vec::with_capacity(vtx_count);
                    for _ in 0..vtx_count {
                        let x = LittleEndian::read_f64(&slice[cursor..cursor + 8]);
                        let y = LittleEndian::read_f64(&slice[cursor + 8..cursor + 16]);
                        pts.push([x, y]);
                        cursor += 16;
                    }
                    let feat_len = 8 + byte_needed;
                    let (geom_score, notes) = if pts.len() == 1 {
                        let ok = pts[0][0].is_finite() && pts[0][1].is_finite();
                        (
                            if ok { 0.90 } else { 0.0 },
                            vec!["Single 2D point coordinate".to_string()],
                        )
                    } else {
                        score_coordinate_sequence_2d(&pts)
                    };

                    let geometry = match geom_kind {
                        1 if pts.len() == 1 => Geometry::Point {
                            coord: pts[0],
                            z: None,
                        },
                        1 => Geometry::MultiPoint { coords: pts },
                        2 => Geometry::LineString { coords: pts },
                        3 => Geometry::Polygon { rings: vec![pts] },
                        4 => Geometry::CubicBezier {
                            control_points: pts,
                        },
                        _ => Geometry::LineString { coords: pts },
                    };

                    let mut props = BTreeMap::new();
                    props.insert(
                        "record_id".to_string(),
                        AttributeValue::Int(feat_id_num as i64),
                    );
                    props.insert(
                        "layer".to_string(),
                        AttributeValue::Text(layer_name.clone()),
                    );
                    props.insert(
                        "stream_lineage".to_string(),
                        AttributeValue::Text(stream_lineage.to_string()),
                    );

                    let conf = build_confidence(
                        0.96,
                        ptr_validity,
                        &data[feat_start..feat_start + feat_len],
                        geom_score,
                        notes,
                    );
                    let bbox = geometry.bounding_box();
                    features.push(GeometricFeature {
                        id: format!("feat_{}_{}", idx, f_idx),
                        layer_id: layer_id.clone(),
                        geometry,
                        bbox,
                        properties: props,
                        provenance: Provenance {
                            id: format!("prov_feat_{}_{}", idx, f_idx),
                            span: ByteSpan::new(feat_start, feat_len),
                            detector: "StructuredVectorSectionDetector".to_string(),
                            endianness: "LITTLE_ENDIAN".to_string(),
                            stream_lineage: stream_lineage.to_string(),
                            host_compressed_span,
                            confidence: conf,
                        },
                    });
                }

                let (stroke, fill) = LAYER_PALETTE[layers.len() % LAYER_PALETTE.len()];
                layers.push(Layer {
                    id: layer_id,
                    name: layer_name,
                    style_stroke: stroke.to_string(),
                    style_fill: fill.to_string(),
                    features,
                    bbox: None,
                });
            }
            3 if sec_len >= 24 && sec_len % 24 == 0 => {
                let stride = 24usize;
                let count = sec_len / stride;
                let mut rows = Vec::with_capacity(count);
                for r in 0..count {
                    let r_slice = &slice[r * stride..(r + 1) * stride];
                    let id_val = LittleEndian::read_u32(&r_slice[0..4]) as i64;
                    let metric_val = LittleEndian::read_f32(&r_slice[4..8]) as f64;
                    let label = String::from_utf8_lossy(&r_slice[8..24])
                        .trim_end_matches('\0')
                        .trim()
                        .to_string();
                    let mut row = BTreeMap::new();
                    row.insert("record_id".to_string(), AttributeValue::Int(id_val));
                    row.insert(
                        "measurement".to_string(),
                        AttributeValue::Float((metric_val * 10000.0).round() / 10000.0),
                    );
                    row.insert("label".to_string(), AttributeValue::Text(label));
                    rows.push(row);
                }
                attribute_tables.push(AttributeTable {
                    id: format!("table_{}", idx),
                    name: format!("recovered_attributes_{}", idx),
                    record_stride: stride,
                    record_count: count,
                    columns: vec![
                        ColumnSchema {
                            name: "record_id".to_string(),
                            data_type: "UINT32".to_string(),
                            byte_offset_in_record: 0,
                            byte_width: 4,
                        },
                        ColumnSchema {
                            name: "measurement".to_string(),
                            data_type: "FLOAT32".to_string(),
                            byte_offset_in_record: 4,
                            byte_width: 4,
                        },
                        ColumnSchema {
                            name: "label".to_string(),
                            data_type: "ASCII_16".to_string(),
                            byte_offset_in_record: 8,
                            byte_width: 16,
                        },
                    ],
                    rows,
                    provenance: Provenance {
                        id: format!("prov_table_{}", idx),
                        span: ByteSpan::new(sec_off, sec_len),
                        detector: "RepeatingRecordDetector".to_string(),
                        endianness: "LITTLE_ENDIAN".to_string(),
                        stream_lineage: stream_lineage.to_string(),
                        host_compressed_span,
                        confidence: build_confidence(
                            0.95,
                            ptr_validity,
                            slice,
                            0.90,
                            vec![format!(
                                "Fixed stride = {} bytes across {} records",
                                stride, count
                            )],
                        ),
                    },
                });
            }
            4 if sec_len >= 40 => {
                let ox = LittleEndian::read_f64(&slice[0..8]);
                let oy = LittleEndian::read_f64(&slice[8..16]);
                let sx = LittleEndian::read_f64(&slice[16..24]);
                let sy = LittleEndian::read_f64(&slice[24..32]);
                let cols = LittleEndian::read_u32(&slice[32..36]) as usize;
                let rows = LittleEndian::read_u32(&slice[36..40]) as usize;
                let expected = 40 + cols * rows * 4;
                if expected <= sec_len && cols > 1 && rows > 1 {
                    let mut values = Vec::with_capacity(cols * rows);
                    for i in 0..(cols * rows) {
                        let base = 40 + i * 4;
                        let v = LittleEndian::read_f32(&slice[base..base + 4]) as f64;
                        values.push((v * 10000.0).round() / 10000.0);
                    }
                    let geom = Geometry::RegularGrid {
                        origin: [ox, oy],
                        spacing: [sx, sy],
                        dims: [cols, rows],
                        values,
                    };
                    let bbox = geom.bounding_box();
                    let mut props = BTreeMap::new();
                    props.insert("grid_cols".to_string(), AttributeValue::Int(cols as i64));
                    props.insert("grid_rows".to_string(), AttributeValue::Int(rows as i64));
                    props.insert(
                        "stream_lineage".to_string(),
                        AttributeValue::Text(stream_lineage.to_string()),
                    );

                    let (stroke, fill) = LAYER_PALETTE[layers.len() % LAYER_PALETTE.len()];
                    layers.push(Layer {
                        id: format!("layer_grid_{}", idx),
                        name: format!("regular_grid_{}", idx),
                        style_stroke: stroke.to_string(),
                        style_fill: fill.to_string(),
                        features: vec![GeometricFeature {
                            id: format!("feat_grid_{}", idx),
                            layer_id: format!("layer_grid_{}", idx),
                            geometry: geom,
                            bbox,
                            properties: props,
                            provenance: Provenance {
                                id: format!("prov_grid_{}", idx),
                                span: ByteSpan::new(sec_off, sec_len),
                                detector: "RegularGridDetector".to_string(),
                                endianness: "LITTLE_ENDIAN".to_string(),
                                stream_lineage: stream_lineage.to_string(),
                                host_compressed_span,
                                confidence: build_confidence(
                                    0.95,
                                    ptr_validity,
                                    slice,
                                    0.94,
                                    vec![format!(
                                        "Regular {}x{} float32 lattice with spacing ({}, {})",
                                        cols, rows, sx, sy
                                    )],
                                ),
                            },
                        }],
                        bbox,
                    });
                }
            }
            5 if sec_len >= 48 => {
                let width = LittleEndian::read_u32(&slice[0..4]);
                let height = LittleEndian::read_u32(&slice[4..8]);
                let channels = slice[8];
                let min_x = LittleEndian::read_f64(&slice[16..24]);
                let min_y = LittleEndian::read_f64(&slice[24..32]);
                let max_x = LittleEndian::read_f64(&slice[32..40]);
                let max_y = LittleEndian::read_f64(&slice[40..48]);
                let pix_bytes = (width as usize) * (height as usize) * (channels as usize);
                if 48 + pix_bytes <= sec_len && width > 0 && height > 0 {
                    raster_tiles.push(RasterTile {
                        id: format!("raster_tile_{}", idx),
                        width,
                        height,
                        channels,
                        bit_depth: 8,
                        format: if channels == 3 {
                            "RAW_RGB8".to_string()
                        } else {
                            "RAW_GRAY8".to_string()
                        },
                        georef_bbox: Some(BoundingBox {
                            min_x,
                            min_y,
                            max_x,
                            max_y,
                            min_z: None,
                            max_z: None,
                        }),
                        exported_path: None,
                        data: slice[48..48 + pix_bytes].to_vec(),
                        provenance: Provenance {
                            id: format!("prov_raster_{}", idx),
                            span: ByteSpan::new(sec_off, sec_len),
                            detector: "RasterTileDetector".to_string(),
                            endianness: "LITTLE_ENDIAN".to_string(),
                            stream_lineage: stream_lineage.to_string(),
                            host_compressed_span,
                            confidence: build_confidence(
                                0.96,
                                ptr_validity,
                                slice,
                                0.92,
                                vec![format!(
                                    "Recovered {}x{}x{} uncompressed raster tile",
                                    width, height, channels
                                )],
                            ),
                        },
                    });
                }
            }
            _ => {
                if !is_already_claimed {
                    let ent = shannon_entropy(slice);
                    let mut meta = BTreeMap::new();
                    meta.insert(
                        "section_type_tag".to_string(),
                        AttributeValue::Int(sec_type as i64),
                    );
                    meta.insert(
                        "section_flags".to_string(),
                        AttributeValue::Int(sec_meta as i64),
                    );
                    embedded_assets.push(EmbeddedAsset {
                        id: format!("asset_opaque_{}", idx),
                        kind: "OPAQUE_COMPRESSED_OR_ENCRYPTED".to_string(),
                        description: format!(
                            "Opaque/encrypted payload block (entropy {:.2} bits/byte); preserved as-is without decryption attempt",
                            ent
                        ),
                        entropy: ent,
                        is_opaque: true,
                        metadata: meta,
                        provenance: Provenance {
                            id: format!("prov_opaque_{}", idx),
                            span: ByteSpan::new(sec_off, sec_len),
                            detector: "EntropyOpaqueClassifier".to_string(),
                            endianness: "UNKNOWN".to_string(),
                            stream_lineage: stream_lineage.to_string(),
                            host_compressed_span,
                            confidence: ConfidenceBreakdown::compute(
                                0.95,
                                ptr_validity,
                                0.95,
                                0.85,
                                vec![format!(
                                    "High Shannon entropy ({:.3} bits/byte) not matching standard Deflate/zlib/gzip streams",
                                    ent
                                )],
                            ),
                        },
                    });
                }
            }
        }
    }
}

fn parse_shapefile_records(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    layers: &mut Vec<Layer>,
    crs_hint: &mut CoordinateSystemHint,
) {
    if data.len() < 100 {
        return;
    }
    tracker.claim(0, 100);
    let min_x = LittleEndian::read_f64(&data[36..44]);
    let min_y = LittleEndian::read_f64(&data[44..52]);
    if (-180.0..=180.0).contains(&min_x) && (-90.0..=90.0).contains(&min_y) {
        crs_hint.crs_type = "WGS84_LON_LAT".to_string();
        crs_hint.epsg_hint = Some(4326);
        crs_hint.units = "degrees".to_string();
    }

    let mut cursor = 100usize;
    let mut features = Vec::new();
    while cursor + 12 <= data.len() {
        let rec_start = cursor;
        let rec_num = BigEndian::read_u32(&data[cursor..cursor + 4]);
        let content_words = BigEndian::read_u32(&data[cursor + 4..cursor + 8]) as usize;
        let content_bytes = content_words * 2;
        if cursor + 8 + content_bytes > data.len() || content_bytes < 4 {
            break;
        }
        let rec_slice = &data[cursor + 8..cursor + 8 + content_bytes];
        let shape_type = LittleEndian::read_u32(&rec_slice[0..4]);

        match shape_type {
            1 if rec_slice.len() >= 20 => {
                let x = LittleEndian::read_f64(&rec_slice[4..12]);
                let y = LittleEndian::read_f64(&rec_slice[12..20]);
                let geom = Geometry::Point {
                    coord: [x, y],
                    z: None,
                };
                let bbox = geom.bounding_box();
                let mut props = BTreeMap::new();
                props.insert(
                    "record_number".to_string(),
                    AttributeValue::Int(rec_num as i64),
                );
                props.insert(
                    "stream_lineage".to_string(),
                    AttributeValue::Text(stream_lineage.to_string()),
                );
                features.push(GeometricFeature {
                    id: format!("shp_pt_{}", rec_num),
                    layer_id: "layer_shp_0".to_string(),
                    geometry: geom,
                    bbox,
                    properties: props,
                    provenance: Provenance {
                        id: format!("prov_shp_{}", rec_num),
                        span: ByteSpan::new(rec_start, 8 + content_bytes),
                        detector: "ShapefileRecordDetector".to_string(),
                        endianness: "MIXED_BE_LE".to_string(),
                        stream_lineage: stream_lineage.to_string(),
                        host_compressed_span,
                        confidence: build_confidence(
                            0.98,
                            1.0,
                            &data[rec_start..rec_start + 8 + content_bytes],
                            0.95,
                            vec!["Valid Esri Shapefile Point record".to_string()],
                        ),
                    },
                });
            }
            3 | 5 if rec_slice.len() >= 44 => {
                let num_parts = LittleEndian::read_u32(&rec_slice[36..40]) as usize;
                let num_points = LittleEndian::read_u32(&rec_slice[40..44]) as usize;
                let parts_end = 44 + num_parts * 4;
                let pts_end = parts_end + num_points * 16;
                if pts_end <= rec_slice.len() && num_points >= 2 {
                    let mut parts = Vec::with_capacity(num_parts);
                    for p in 0..num_parts {
                        let idx =
                            LittleEndian::read_u32(&rec_slice[44 + p * 4..48 + p * 4]) as usize;
                        parts.push(idx);
                    }
                    let mut all_pts = Vec::with_capacity(num_points);
                    for i in 0..num_points {
                        let base = parts_end + i * 16;
                        let x = LittleEndian::read_f64(&rec_slice[base..base + 8]);
                        let y = LittleEndian::read_f64(&rec_slice[base + 8..base + 16]);
                        all_pts.push([x, y]);
                    }
                    let mut rings = Vec::new();
                    for (p_idx, &start_i) in parts.iter().enumerate() {
                        let end_i = parts.get(p_idx + 1).copied().unwrap_or(num_points);
                        if start_i < end_i && end_i <= all_pts.len() {
                            rings.push(all_pts[start_i..end_i].to_vec());
                        }
                    }
                    let (g_score, notes) = score_coordinate_sequence_2d(&all_pts);
                    let geom = if shape_type == 5 {
                        Geometry::Polygon { rings }
                    } else if rings.len() == 1 {
                        Geometry::LineString {
                            coords: rings.remove(0),
                        }
                    } else {
                        Geometry::MultiLineString { lines: rings }
                    };
                    let bbox = geom.bounding_box();
                    let mut props = BTreeMap::new();
                    props.insert(
                        "record_number".to_string(),
                        AttributeValue::Int(rec_num as i64),
                    );
                    props.insert(
                        "stream_lineage".to_string(),
                        AttributeValue::Text(stream_lineage.to_string()),
                    );
                    features.push(GeometricFeature {
                        id: format!("shp_feat_{}", rec_num),
                        layer_id: "layer_shp_0".to_string(),
                        geometry: geom,
                        bbox,
                        properties: props,
                        provenance: Provenance {
                            id: format!("prov_shp_{}", rec_num),
                            span: ByteSpan::new(rec_start, 8 + content_bytes),
                            detector: "ShapefileRecordDetector".to_string(),
                            endianness: "MIXED_BE_LE".to_string(),
                            stream_lineage: stream_lineage.to_string(),
                            host_compressed_span,
                            confidence: build_confidence(
                                0.98,
                                1.0,
                                &data[rec_start..rec_start + 8 + content_bytes],
                                g_score,
                                notes,
                            ),
                        },
                    });
                }
            }
            _ => {}
        }
        tracker.claim(rec_start, 8 + content_bytes);
        cursor += 8 + content_bytes;
    }

    if !features.is_empty() {
        let (stroke, fill) = LAYER_PALETTE[layers.len() % LAYER_PALETTE.len()];
        layers.push(Layer {
            id: "layer_shp_0".to_string(),
            name: "shapefile_vectors".to_string(),
            style_stroke: stroke.to_string(),
            style_fill: fill.to_string(),
            features,
            bbox: None,
        });
    }
}

fn detect_offset_tables(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    embedded_assets: &mut Vec<EmbeddedAsset>,
) {
    if data.len() < 32 {
        return;
    }
    let mut offset = 0usize;
    while offset + 20 <= data.len() {
        if tracker.is_claimed(offset, 20) {
            offset += 4;
            continue;
        }
        let count = LittleEndian::read_u32(&data[offset..offset + 4]) as usize;
        if (4..=256).contains(&count) && offset + 4 + count * 4 <= data.len() {
            let mut valid = true;
            let mut prev = 0usize;
            for i in 0..count {
                let ptr =
                    LittleEndian::read_u32(&data[offset + 4 + i * 4..offset + 8 + i * 4]) as usize;
                if ptr <= prev || ptr >= data.len() {
                    valid = false;
                    break;
                }
                prev = ptr;
            }
            if valid {
                let byte_len = 4 + count * 4;
                tracker.claim(offset, byte_len);
                let slice = &data[offset..offset + byte_len];
                let mut meta = BTreeMap::new();
                meta.insert(
                    "pointer_count".to_string(),
                    AttributeValue::Int(count as i64),
                );
                embedded_assets.push(EmbeddedAsset {
                    id: format!("asset_ptrtab_{:#x}", offset),
                    kind: "OFFSET_TABLE".to_string(),
                    description: format!(
                        "Monotonic u32 offset table ({} valid stream pointers)",
                        count
                    ),
                    entropy: shannon_entropy(slice),
                    is_opaque: false,
                    metadata: meta,
                    provenance: Provenance {
                        id: format!("prov_ptrtab_{:#x}", offset),
                        span: ByteSpan::new(offset, byte_len),
                        detector: "SlidingOffsetTableDetector".to_string(),
                        endianness: "LITTLE_ENDIAN".to_string(),
                        stream_lineage: stream_lineage.to_string(),
                        host_compressed_span,
                        confidence: build_confidence(
                            0.92,
                            1.0,
                            slice,
                            0.85,
                            vec![format!(
                                "{} strictly increasing offsets within stream size {}",
                                count,
                                data.len()
                            )],
                        ),
                    },
                });
                offset += byte_len;
                continue;
            }
        }
        offset += 4;
    }
}

fn detect_embedded_rasters(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    raster_tiles: &mut Vec<RasterTile>,
) {
    let png_sig = b"\x89PNG\r\n\x1a\n";
    let iend_sig = b"IEND";
    if data.len() < 32 {
        return;
    }
    let mut i = 0usize;
    while i + 32 <= data.len() {
        if !tracker.is_claimed(i, 16) && &data[i..i + 8] == png_sig {
            if let Some(rel_end) = data[i + 8..].windows(4).position(|w| w == iend_sig) {
                let total_len = (8 + rel_end + 8).min(data.len() - i);
                let width = BigEndian::read_u32(&data[i + 16..i + 20]);
                let height = BigEndian::read_u32(&data[i + 20..i + 24]);
                let bit_depth = data[i + 24];
                tracker.claim(i, total_len);
                raster_tiles.push(RasterTile {
                    id: format!("raster_png_{:#x}", i),
                    width,
                    height,
                    channels: 4,
                    bit_depth,
                    format: "EMBEDDED_PNG".to_string(),
                    georef_bbox: None,
                    exported_path: None,
                    data: data[i..i + total_len].to_vec(),
                    provenance: Provenance {
                        id: format!("prov_png_{:#x}", i),
                        span: ByteSpan::new(i, total_len),
                        detector: "EmbeddedPngSignatureDetector".to_string(),
                        endianness: "BIG_ENDIAN".to_string(),
                        stream_lineage: stream_lineage.to_string(),
                        host_compressed_span,
                        confidence: build_confidence(
                            0.99,
                            1.0,
                            &data[i..i + total_len],
                            0.95,
                            vec![format!(
                                "Embedded PNG stream ({}x{}, {} bytes)",
                                width, height, total_len
                            )],
                        ),
                    },
                });
                i += total_len;
                continue;
            }
        }
        i += 1;
    }
}

fn detect_coordinate_sequences(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    layers: &mut Vec<Layer>,
    crs_hint: &mut CoordinateSystemHint,
) {
    if data.len() < 48 {
        return;
    }
    let mut features = Vec::new();
    let mut offset = 0usize;
    let layer_id = if stream_lineage == "root" {
        "layer_heuristic_f64".to_string()
    } else {
        format!("layer_decompressed_{}", layers.len())
    };

    while offset + 36 <= data.len() {
        if tracker.is_claimed(offset, 36) {
            offset += 4;
            continue;
        }

        let maybe_count = LittleEndian::read_u32(&data[offset..offset + 4]) as usize;
        if (3..=10_000).contains(&maybe_count) {
            let byte_len = 4 + maybe_count * 16;
            if offset + byte_len <= data.len() && !tracker.is_claimed(offset, byte_len) {
                let mut pts = Vec::with_capacity(maybe_count);
                for v in 0..maybe_count {
                    let base = offset + 4 + v * 16;
                    let x = LittleEndian::read_f64(&data[base..base + 8]);
                    let y = LittleEndian::read_f64(&data[base + 8..base + 16]);
                    pts.push([x, y]);
                }
                let (geom_score, notes) = score_coordinate_sequence_2d(&pts);
                if geom_score >= 0.65 {
                    tracker.claim(offset, byte_len);
                    let closed = {
                        let first = pts[0];
                        let last = pts[pts.len() - 1];
                        pts.len() >= 4
                            && ((first[0] - last[0]).powi(2) + (first[1] - last[1]).powi(2)).sqrt()
                                < 1e-4
                    };
                    let geom = if closed {
                        Geometry::Polygon { rings: vec![pts] }
                    } else {
                        Geometry::LineString { coords: pts }
                    };
                    let bbox = geom.bounding_box();
                    if let Some(b) = &bbox {
                        if b.min_x >= -180.0
                            && b.max_x <= 180.0
                            && b.min_y >= -90.0
                            && b.max_y <= 90.0
                        {
                            crs_hint.crs_type = "WGS84_LON_LAT".to_string();
                            crs_hint.epsg_hint = Some(4326);
                            crs_hint.units = "degrees".to_string();
                        }
                    }
                    let mut props = BTreeMap::new();
                    props.insert(
                        "vertex_count".to_string(),
                        AttributeValue::Int(maybe_count as i64),
                    );
                    props.insert(
                        "encoding".to_string(),
                        AttributeValue::Text("LENGTH_PREFIXED_F64_LE".to_string()),
                    );
                    props.insert(
                        "stream_lineage".to_string(),
                        AttributeValue::Text(stream_lineage.to_string()),
                    );
                    features.push(GeometricFeature {
                        id: format!("feat_f64_{}_{:#x}", layers.len(), offset),
                        layer_id: layer_id.clone(),
                        geometry: geom,
                        bbox,
                        properties: props,
                        provenance: Provenance {
                            id: format!("prov_f64_{}_{:#x}", layers.len(), offset),
                            span: ByteSpan::new(offset, byte_len),
                            detector: "SlidingWindowFloat64Detector".to_string(),
                            endianness: "LITTLE_ENDIAN".to_string(),
                            stream_lineage: stream_lineage.to_string(),
                            host_compressed_span,
                            confidence: build_confidence(
                                0.92,
                                0.85,
                                &data[offset..offset + byte_len],
                                geom_score,
                                notes,
                            ),
                        },
                    });
                    offset += byte_len;
                    continue;
                }
            }

            let byte_len_f32 = 4 + maybe_count * 8;
            if offset + byte_len_f32 <= data.len() && !tracker.is_claimed(offset, byte_len_f32) {
                let mut pts = Vec::with_capacity(maybe_count);
                for v in 0..maybe_count {
                    let base = offset + 4 + v * 8;
                    let x = LittleEndian::read_f32(&data[base..base + 4]) as f64;
                    let y = LittleEndian::read_f32(&data[base + 4..base + 8]) as f64;
                    pts.push([x, y]);
                }
                let (geom_score, notes) = score_coordinate_sequence_2d(&pts);
                if geom_score >= 0.70 {
                    tracker.claim(offset, byte_len_f32);
                    let geom = Geometry::LineString { coords: pts };
                    let bbox = geom.bounding_box();
                    let mut props = BTreeMap::new();
                    props.insert(
                        "vertex_count".to_string(),
                        AttributeValue::Int(maybe_count as i64),
                    );
                    props.insert(
                        "encoding".to_string(),
                        AttributeValue::Text("LENGTH_PREFIXED_F32_LE".to_string()),
                    );
                    props.insert(
                        "stream_lineage".to_string(),
                        AttributeValue::Text(stream_lineage.to_string()),
                    );
                    features.push(GeometricFeature {
                        id: format!("feat_f32_{}_{:#x}", layers.len(), offset),
                        layer_id: layer_id.clone(),
                        geometry: geom,
                        bbox,
                        properties: props,
                        provenance: Provenance {
                            id: format!("prov_f32_{}_{:#x}", layers.len(), offset),
                            span: ByteSpan::new(offset, byte_len_f32),
                            detector: "SlidingWindowFloat32Detector".to_string(),
                            endianness: "LITTLE_ENDIAN".to_string(),
                            stream_lineage: stream_lineage.to_string(),
                            host_compressed_span,
                            confidence: build_confidence(
                                0.88,
                                0.80,
                                &data[offset..offset + byte_len_f32],
                                geom_score,
                                notes,
                            ),
                        },
                    });
                    offset += byte_len_f32;
                    continue;
                }
            }
        }
        offset += 4;
    }

    if !features.is_empty() {
        let (stroke, fill) = LAYER_PALETTE[layers.len() % LAYER_PALETTE.len()];
        let layer_name = if stream_lineage == "root" {
            "heuristic_coordinate_runs".to_string()
        } else {
            format!("decompressed_vectors ({})", stream_lineage)
        };
        layers.push(Layer {
            id: layer_id,
            name: layer_name,
            style_stroke: stroke.to_string(),
            style_fill: fill.to_string(),
            features,
            bbox: None,
        });
    }
}

fn detect_repeating_records(
    data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    tracker: &mut ClaimTracker,
    attribute_tables: &mut Vec<AttributeTable>,
) {
    let candidate_strides = [16usize, 20, 24, 32, 48, 64];
    if data.len() < 64 {
        return;
    }
    let mut offset = 0usize;
    while offset + 64 <= data.len() {
        if tracker.is_claimed(offset, 48) {
            offset += 4;
            continue;
        }
        let mut matched = false;
        for &stride in &candidate_strides {
            if offset + stride * 4 > data.len() {
                continue;
            }
            let first_id = LittleEndian::read_u32(&data[offset..offset + 4]);
            if first_id == 0 || first_id > 100_000 {
                continue;
            }
            let mut count = 1usize;
            while offset + (count + 1) * stride <= data.len()
                && !tracker.is_claimed(offset + count * stride, stride)
            {
                let next_id = LittleEndian::read_u32(
                    &data[offset + count * stride..offset + count * stride + 4],
                );
                if next_id == first_id + (count as u32) {
                    count += 1;
                } else {
                    break;
                }
            }
            if count >= 4 {
                let total_bytes = count * stride;
                tracker.claim(offset, total_bytes);
                let slice = &data[offset..offset + total_bytes];
                let mut rows = Vec::with_capacity(count);
                for r in 0..count {
                    let r_slice = &slice[r * stride..(r + 1) * stride];
                    let rec_id = LittleEndian::read_u32(&r_slice[0..4]) as i64;
                    let val_f32 = LittleEndian::read_f32(&r_slice[4..8]) as f64;
                    let ascii_part = String::from_utf8_lossy(&r_slice[8..stride.min(24)])
                        .trim_end_matches('\0')
                        .trim()
                        .to_string();
                    let mut map = BTreeMap::new();
                    map.insert("record_id".to_string(), AttributeValue::Int(rec_id));
                    if val_f32.is_finite() && val_f32.abs() < 1e8 {
                        map.insert(
                            "field_f32".to_string(),
                            AttributeValue::Float((val_f32 * 10000.0).round() / 10000.0),
                        );
                    }
                    map.insert("ascii_payload".to_string(), AttributeValue::Text(ascii_part));
                    rows.push(map);
                }
                let tbl_idx = attribute_tables.len();
                attribute_tables.push(AttributeTable {
                    id: format!("table_heuristic_{}_{:#x}", tbl_idx, offset),
                    name: format!("heuristic_records_{:#x}", offset),
                    record_stride: stride,
                    record_count: count,
                    columns: vec![
                        ColumnSchema {
                            name: "record_id".to_string(),
                            data_type: "UINT32".to_string(),
                            byte_offset_in_record: 0,
                            byte_width: 4,
                        },
                        ColumnSchema {
                            name: "field_f32".to_string(),
                            data_type: "FLOAT32".to_string(),
                            byte_offset_in_record: 4,
                            byte_width: 4,
                        },
                        ColumnSchema {
                            name: "ascii_payload".to_string(),
                            data_type: "ASCII".to_string(),
                            byte_offset_in_record: 8,
                            byte_width: stride - 8,
                        },
                    ],
                    rows,
                    provenance: Provenance {
                        id: format!("prov_table_{}_{:#x}", tbl_idx, offset),
                        span: ByteSpan::new(offset, total_bytes),
                        detector: "SlidingStrideRecordDetector".to_string(),
                        endianness: "LITTLE_ENDIAN".to_string(),
                        stream_lineage: stream_lineage.to_string(),
                        host_compressed_span,
                        confidence: build_confidence(
                            0.90,
                            0.85,
                            slice,
                            0.85,
                            vec![format!(
                                "Sequential u32 key with fixed stride {} across {} records",
                                stride, count
                            )],
                        ),
                    },
                });
                offset += total_bytes;
                matched = true;
                break;
            }
        }
        if !matched {
            offset += 4;
        }
    }
}

fn detect_opaque_regions(
    _data: &[u8],
    stream_lineage: &str,
    host_compressed_span: Option<ByteSpan>,
    entropy_profile: &[EntropyWindow],
    tracker: &mut ClaimTracker,
    embedded_assets: &mut Vec<EmbeddedAsset>,
) {
    for win in entropy_profile {
        if win.classification == "HIGH_COMPRESSED_OR_OPAQUE"
            && !tracker.is_claimed(win.offset, win.length)
        {
            tracker.claim(win.offset, win.length);
            let mut meta = BTreeMap::new();
            meta.insert(
                "window_entropy".to_string(),
                AttributeValue::Float(win.shannon_entropy),
            );
            embedded_assets.push(EmbeddedAsset {
                id: format!("asset_opaque_{:#x}", win.offset),
                kind: "OPAQUE_COMPRESSED_OR_ENCRYPTED".to_string(),
                description: format!(
                    "Unclaimed high-entropy region ({:.2} bits/byte); reported as opaque/encrypted without decryption attempt",
                    win.shannon_entropy
                ),
                entropy: win.shannon_entropy,
                is_opaque: true,
                metadata: meta,
                provenance: Provenance {
                    id: format!("prov_opaque_{:#x}", win.offset),
                    span: ByteSpan::new(win.offset, win.length),
                    detector: "SlidingEntropyClassifier".to_string(),
                    endianness: "UNKNOWN".to_string(),
                    stream_lineage: stream_lineage.to_string(),
                    host_compressed_span,
                    confidence: ConfidenceBreakdown::compute(
                        0.90,
                        0.80,
                        0.95,
                        0.80,
                        vec!["High byte entropy not matching standard Deflate/zlib/gzip streams".to_string()],
                    ),
                },
            });
        }
    }
}
