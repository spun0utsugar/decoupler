use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Represents an exact byte range in the original source binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub offset: usize,
    pub length: usize,
}

impl ByteSpan {
    pub fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    pub fn end(&self) -> usize {
        self.offset.saturating_add(self.length)
    }
}

/// Multi-factor confidence breakdown explaining why a structure was scored as it was.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    /// Overall composite score in `[0.0, 1.0]`.
    pub composite: f64,
    /// Alignment and validity of internal numeric/pointer invariants `[0.0, 1.0]`.
    pub internal_consistency: f64,
    /// Validity of pointer/offset references into file boundaries `[0.0, 1.0]`.
    pub pointer_validity: f64,
    /// Appropriateness of Shannon entropy for the hypothesized structure `[0.0, 1.0]`.
    pub entropy_score: f64,
    /// Geometric plausibility (finite bounds, spatial continuity, non-degenerate rings) `[0.0, 1.0]`.
    pub geometric_plausibility: f64,
    /// Human-readable rationale notes.
    pub notes: Vec<String>,
}

impl ConfidenceBreakdown {
    pub fn compute(
        internal_consistency: f64,
        pointer_validity: f64,
        entropy_score: f64,
        geometric_plausibility: f64,
        notes: Vec<String>,
    ) -> Self {
        let composite = (0.30 * internal_consistency
            + 0.20 * pointer_validity
            + 0.15 * entropy_score
            + 0.35 * geometric_plausibility)
            .clamp(0.0, 1.0);
        let composite = (composite * 10000.0).round() / 10000.0;
        Self {
            composite,
            internal_consistency: (internal_consistency * 10000.0).round() / 10000.0,
            pointer_validity: (pointer_validity * 10000.0).round() / 10000.0,
            entropy_score: (entropy_score * 10000.0).round() / 10000.0,
            geometric_plausibility: (geometric_plausibility * 10000.0).round() / 10000.0,
            notes,
        }
    }
}

/// Provenance attached to every recovered entity in the Intermediate Representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub id: String,
    pub span: ByteSpan,
    pub detector: String,
    pub endianness: String,
    /// Virtual sub-stream lineage (e.g., `"root"` or `"parent_offset:0x1200/decompressed_0"`).
    pub stream_lineage: String,
    /// Outer compressed byte span in the host binary when recovered from a decompressed child stream.
    pub host_compressed_span: Option<ByteSpan>,
    pub confidence: ConfidenceBreakdown,
}

/// Summary metadata for a carved and decompressed virtual child stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecompressedStreamInfo {
    pub stream_id: String,
    pub parent_lineage: String,
    pub depth: usize,
    pub codec: String, // "ZLIB_RFC1950", "GZIP_RFC1952", "RAW_DEFLATE"
    pub host_offset: usize,
    pub compressed_length: usize,
    pub decompressed_length: usize,
    pub expansion_ratio: f64,
    pub sha256: String,
}

/// Document-level metadata and overall scan diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub source_filename: String,
    pub file_size: usize,
    pub sha256: String,
    pub detected_magic: String,
    pub format_family: String,
    pub overall_entropy: f64,
    pub endianness_hint: String,
    pub tool_version: String,
}

/// Axis-aligned bounding box in 2D or 3D.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub min_x: f64,
    pub min_y: f64,
    pub max_x: f64,
    pub max_y: f64,
    pub min_z: Option<f64>,
    pub max_z: Option<f64>,
}

impl BoundingBox {
    pub fn from_points_2d(pts: &[[f64; 2]]) -> Option<Self> {
        if pts.is_empty() {
            return None;
        }
        let mut min_x = f64::INFINITY;
        let mut min_y = f64::INFINITY;
        let mut max_x = f64::NEG_INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        for &[x, y] in pts {
            if x < min_x {
                min_x = x;
            }
            if y < min_y {
                min_y = y;
            }
            if x > max_x {
                max_x = x;
            }
            if y > max_y {
                max_y = y;
            }
        }
        Some(Self {
            min_x,
            min_y,
            max_x,
            max_y,
            min_z: None,
            max_z: None,
        })
    }

    pub fn merge(&self, other: &Self) -> Self {
        Self {
            min_x: self.min_x.min(other.min_x),
            min_y: self.min_y.min(other.min_y),
            max_x: self.max_x.max(other.max_x),
            max_y: self.max_y.max(other.max_y),
            min_z: match (self.min_z, other.min_z) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            max_z: match (self.max_z, other.max_z) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
        }
    }
}

/// Coordinate system and optional 2D/3D affine transformation hint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoordinateSystemHint {
    pub crs_type: String, // e.g., "LOCAL_CARTESIAN", "WGS84_LON_LAT", "PROJECTED_METERS", "NORMALIZED_VIEWPORT"
    pub epsg_hint: Option<u32>,
    /// 6-parameter 2D affine matrix `[a, b, c, d, tx, ty]` where:
    /// `x' = a*x + b*y + tx`, `y' = c*x + d*y + ty`
    pub affine_matrix: Option<[f64; 6]>,
    pub units: String,
    pub provenance: Option<Provenance>,
}

/// Strongly-typed geometry variants preserving exact original floating-point values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Geometry {
    Point {
        coord: [f64; 2],
        z: Option<f64>,
    },
    MultiPoint {
        coords: Vec<[f64; 2]>,
    },
    LineString {
        coords: Vec<[f64; 2]>,
    },
    MultiLineString {
        lines: Vec<Vec<[f64; 2]>>,
    },
    Polygon {
        /// First ring is exterior, subsequent rings are interior holes.
        rings: Vec<Vec<[f64; 2]>>,
    },
    MultiPolygon {
        polygons: Vec<Vec<Vec<[f64; 2]>>>,
    },
    CubicBezier {
        /// Sequence of `[x, y]` control points (`3*n + 1` points: `[P0, C1, C2, P1, ...]`).
        control_points: Vec<[f64; 2]>,
    },
    SimpleMesh {
        vertices: Vec<[f64; 3]>,
        faces: Vec<[u32; 3]>,
    },
    RegularGrid {
        origin: [f64; 2],
        spacing: [f64; 2],
        dims: [usize; 2],
        values: Vec<f64>,
    },
}

impl Geometry {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Geometry::Point { .. } => "Point",
            Geometry::MultiPoint { .. } => "MultiPoint",
            Geometry::LineString { .. } => "LineString",
            Geometry::MultiLineString { .. } => "MultiLineString",
            Geometry::Polygon { .. } => "Polygon",
            Geometry::MultiPolygon { .. } => "MultiPolygon",
            Geometry::CubicBezier { .. } => "CubicBezier",
            Geometry::SimpleMesh { .. } => "SimpleMesh",
            Geometry::RegularGrid { .. } => "RegularGrid",
        }
    }

    pub fn bounding_box(&self) -> Option<BoundingBox> {
        match self {
            Geometry::Point { coord, z } => Some(BoundingBox {
                min_x: coord[0],
                min_y: coord[1],
                max_x: coord[0],
                max_y: coord[1],
                min_z: *z,
                max_z: *z,
            }),
            Geometry::MultiPoint { coords }
            | Geometry::LineString { coords }
            | Geometry::CubicBezier {
                control_points: coords,
            } => BoundingBox::from_points_2d(coords),
            Geometry::MultiLineString { lines } => {
                let flat: Vec<[f64; 2]> = lines.iter().flatten().copied().collect();
                BoundingBox::from_points_2d(&flat)
            }
            Geometry::Polygon { rings } => {
                let flat: Vec<[f64; 2]> = rings.iter().flatten().copied().collect();
                BoundingBox::from_points_2d(&flat)
            }
            Geometry::MultiPolygon { polygons } => {
                let flat: Vec<[f64; 2]> =
                    polygons.iter().flatten().flatten().copied().collect();
                BoundingBox::from_points_2d(&flat)
            }
            Geometry::SimpleMesh { vertices, .. } => {
                if vertices.is_empty() {
                    return None;
                }
                let mut min_x = f64::INFINITY;
                let mut min_y = f64::INFINITY;
                let mut min_z = f64::INFINITY;
                let mut max_x = f64::NEG_INFINITY;
                let mut max_y = f64::NEG_INFINITY;
                let mut max_z = f64::NEG_INFINITY;
                for &[x, y, z] in vertices {
                    min_x = min_x.min(x);
                    min_y = min_y.min(y);
                    min_z = min_z.min(z);
                    max_x = max_x.max(x);
                    max_y = max_y.max(y);
                    max_z = max_z.max(z);
                }
                Some(BoundingBox {
                    min_x,
                    min_y,
                    max_x,
                    max_y,
                    min_z: Some(min_z),
                    max_z: Some(max_z),
                })
            }
            Geometry::RegularGrid {
                origin,
                spacing,
                dims,
                ..
            } => {
                let max_x = origin[0] + spacing[0] * (dims[0].saturating_sub(1) as f64);
                let max_y = origin[1] + spacing[1] * (dims[1].saturating_sub(1) as f64);
                Some(BoundingBox {
                    min_x: origin[0].min(max_x),
                    min_y: origin[1].min(max_y),
                    max_x: origin[0].max(max_x),
                    max_y: origin[1].max(max_y),
                    min_z: None,
                    max_z: None,
                })
            }
        }
    }

    pub fn vertex_count(&self) -> usize {
        match self {
            Geometry::Point { .. } => 1,
            Geometry::MultiPoint { coords }
            | Geometry::LineString { coords }
            | Geometry::CubicBezier {
                control_points: coords,
            } => coords.len(),
            Geometry::MultiLineString { lines } => lines.iter().map(|l| l.len()).sum(),
            Geometry::Polygon { rings } => rings.iter().map(|r| r.len()).sum(),
            Geometry::MultiPolygon { polygons } => {
                polygons.iter().flatten().map(|r| r.len()).sum()
            }
            Geometry::SimpleMesh { vertices, .. } => vertices.len(),
            Geometry::RegularGrid { dims, .. } => dims[0] * dims[1],
        }
    }
}

/// Strongly typed attribute value for feature properties and attribute tables.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    Int(i64),
    Float(f64),
    Text(String),
    Bool(bool),
    BytesHex(String),
    Null,
}

/// A single geometric feature with properties and full byte-level provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeometricFeature {
    pub id: String,
    pub layer_id: String,
    pub geometry: Geometry,
    pub bbox: Option<BoundingBox>,
    pub properties: BTreeMap<String, AttributeValue>,
    pub provenance: Provenance,
}

/// Logical layer or group of geometric features.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Layer {
    pub id: String,
    pub name: String,
    pub style_stroke: String,
    pub style_fill: String,
    pub features: Vec<GeometricFeature>,
    pub bbox: Option<BoundingBox>,
}

/// Column definition in a recovered structured attribute table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnSchema {
    pub name: String,
    pub data_type: String, // "INT32", "FLOAT32", "FLOAT64", "ASCII", "BYTES"
    pub byte_offset_in_record: usize,
    pub byte_width: usize,
}

/// Recovered repeating fixed-stride record table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributeTable {
    pub id: String,
    pub name: String,
    pub record_stride: usize,
    pub record_count: usize,
    pub columns: Vec<ColumnSchema>,
    pub rows: Vec<BTreeMap<String, AttributeValue>>,
    pub provenance: Provenance,
}

/// Recovered raster tile or uncompressed pixel array.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RasterTile {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub channels: u8,
    pub bit_depth: u8,
    pub format: String, // "RAW_RGB8", "RAW_GRAY8", "EMBEDDED_PNG", "EMBEDDED_TIFF"
    pub georef_bbox: Option<BoundingBox>,
    pub exported_path: Option<String>,
    /// Raw pixel or image container bytes (omitted in JSON summary if large, used by exporters).
    #[serde(skip)]
    pub data: Vec<u8>,
    pub provenance: Provenance,
}

/// Embedded block, offset table, or opaque/compressed/encrypted region.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddedAsset {
    pub id: String,
    pub kind: String, // "OFFSET_TABLE", "LENGTH_PREFIXED_BLOCK", "STRING_TABLE", "OPAQUE_COMPRESSED_OR_ENCRYPTED"
    pub description: String,
    pub entropy: f64,
    pub is_opaque: bool,
    pub metadata: BTreeMap<String, AttributeValue>,
    pub provenance: Provenance,
}

/// Entropy window sample across the binary file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyWindow {
    pub offset: usize,
    pub length: usize,
    pub shannon_entropy: f64,
    pub classification: String, // "LOW_STRUCTURED", "MEDIUM_MIXED", "HIGH_COMPRESSED_OR_OPAQUE"
}

/// Complete, human-auditable Intermediate Representation (IR) of a decoupled binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecoupledDocument {
    pub metadata: DocumentMetadata,
    pub coordinate_system: CoordinateSystemHint,
    pub global_bbox: Option<BoundingBox>,
    pub entropy_profile: Vec<EntropyWindow>,
    pub decompressed_streams: Vec<DecompressedStreamInfo>,
    pub layers: Vec<Layer>,
    pub attribute_tables: Vec<AttributeTable>,
    pub raster_tiles: Vec<RasterTile>,
    pub embedded_assets: Vec<EmbeddedAsset>,
}

impl DecoupledDocument {
    pub fn recompute_global_bbox(&mut self) {
        let mut global: Option<BoundingBox> = None;
        for layer in &mut self.layers {
            let mut layer_bbox: Option<BoundingBox> = None;
            for feat in &mut layer.features {
                if feat.bbox.is_none() {
                    feat.bbox = feat.geometry.bounding_box();
                }
                if let Some(b) = &feat.bbox {
                    layer_bbox = Some(match layer_bbox {
                        Some(acc) => acc.merge(b),
                        None => *b,
                    });
                }
            }
            layer.bbox = layer_bbox;
            if let Some(lb) = &layer_bbox {
                global = Some(match global {
                    Some(acc) => acc.merge(lb),
                    None => *lb,
                });
            }
        }
        self.global_bbox = global;
    }

    pub fn total_features(&self) -> usize {
        self.layers.iter().map(|l| l.features.len()).sum()
    }
}
