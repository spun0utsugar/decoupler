#!/usr/bin/env python3
"""
OpenArchive Decoupler (`decouple.py`)
=====================================
Zero-dependency, offline, read-only structural binary analyzer and universal format
decoupler. Mirrors the Rust (`src/`) architecture 1-to-1 using only the Python
standard library (`mmap`, `struct`, `zlib`, `sqlite3`, `hashlib`, `json`, `math`, `argparse`, `tkinter`).

Capabilities:
  1. Read-only memory-mapped ingestion (`mmap.ACCESS_READ`).
  2. Bounded Recursive Stream Carver & Decompressor:
     - Standard Deflate, zlib (RFC 1950: 0x78 0x01 / 0x78 0x9C / 0x78 0xDA), and gzip (RFC 1952: 0x1F 0x8B).
     - Bounded raw Deflate carving on high-entropy regions (> 7.5 bits/byte) preceded by a 4-byte LE or BE length integer.
     - Safety guardrails: max recursion depth = 3, hard cap = 64 MB per buffer, max expansion ratio = 200:1,
       non-blocking fallback on checksum/stream errors.
     - Pass-through pipeline: scans both the raw host binary (`root`) AND all valid decompressed child streams
       (e.g., `parent_offset:0x1200/decompressed_0`), annotating all exported geometries and metadata with exact decompression lineage.
  3. Structural pattern recognition:
     - Validated pointer / offset tables
     - Coordinate sequence detectors (IEEE-754 float64 / float32 runs, polygons, polylines, cubic Beziers)
     - Concrete format extractors (`OADC` CAD/GIS containers, Esri `.shp` Shapefiles)
     - Repeating fixed-stride attribute record detector
     - Regular 2D grid / elevation lattice detector
     - Embedded PNG & raw uncompressed RGB8/Gray8 raster tile detector
     - High-entropy opaque/encrypted block classifier (never attempts decryption)
  4. Strongly-typed Intermediate Representation (IR) with per-entity `ByteSpan`, `stream_lineage`, and
     multi-factor `ConfidenceBreakdown`.
  5. Lossless exporters: SVG, GeoJSON, SQLite, Audit TXT, IR JSON, and Baseline TIFF/PNG.
"""

from __future__ import annotations

import argparse
import dataclasses
from dataclasses import dataclass, field
import hashlib
import json
import math
import mmap
from pathlib import Path
import sqlite3
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple
import zlib

TOOL_VERSION = "0.2.1"

# Carver & Scanner Safety Guardrails
MAX_RECURSION_DEPTH = 3
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024  # 64 MB hard cap per decompressed buffer
MAX_EXPANSION_RATIO = 200.0  # 200:1 ratio limit
MAX_HEURISTIC_SCAN_BYTES = 16 * 1024 * 1024  # 16 MB cap per stream for heuristic coordinate/record passes


@dataclass
class CarverConfig:
    deflate_entropy_threshold: float = 7.20
    min_high_entropy_run: int = 64
    max_recursion_depth: int = 3
    scan_step: int = 32
    aggressive: bool = False
    verbose: bool = False

    def apply_aggressive(self) -> "CarverConfig":
        self.deflate_entropy_threshold = 6.80
        self.max_recursion_depth = 5
        self.scan_step = 16
        self.aggressive = True
        return self

LAYER_PALETTE: List[Tuple[str, str]] = [
    ("#0284c7", "rgba(2, 132, 199, 0.15)"),
    ("#16a34a", "rgba(22, 163, 74, 0.15)"),
    ("#ea580c", "rgba(234, 88, 12, 0.15)"),
    ("#9333ea", "rgba(147, 51, 234, 0.15)"),
    ("#dc2626", "rgba(220, 38, 38, 0.15)"),
    ("#0d9488", "rgba(13, 148, 136, 0.15)"),
]


# ==============================================================================
# 1. INTERMEDIATE REPRESENTATION (IR) DATA MODEL
# ==============================================================================

@dataclass(frozen=True)
class ByteSpan:
    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class ConfidenceBreakdown:
    composite: float
    internal_consistency: float
    pointer_validity: float
    entropy_score: float
    geometric_plausibility: float
    notes: List[str] = field(default_factory=list)

    @staticmethod
    def compute(
        internal_consistency: float,
        pointer_validity: float,
        entropy_score: float,
        geometric_plausibility: float,
        notes: List[str],
    ) -> "ConfidenceBreakdown":
        comp = (
            0.30 * internal_consistency
            + 0.20 * pointer_validity
            + 0.15 * entropy_score
            + 0.35 * geometric_plausibility
        )
        comp = max(0.0, min(1.0, comp))
        return ConfidenceBreakdown(
            composite=round(comp, 4),
            internal_consistency=round(internal_consistency, 4),
            pointer_validity=round(pointer_validity, 4),
            entropy_score=round(entropy_score, 4),
            geometric_plausibility=round(geometric_plausibility, 4),
            notes=notes,
        )


@dataclass
class Provenance:
    id: str
    span: ByteSpan
    detector: str
    endianness: str
    confidence: ConfidenceBreakdown
    stream_lineage: str = "root"
    host_compressed_span: Optional[ByteSpan] = None


@dataclass
class DecompressedStreamInfo:
    stream_id: str
    parent_lineage: str
    depth: int
    codec: str  # "ZLIB_RFC1950", "GZIP_RFC1952", "RAW_DEFLATE"
    host_offset: int
    compressed_length: int
    decompressed_length: int
    expansion_ratio: float
    sha256: str


@dataclass
class BoundingBox:
    min_x: float
    min_y: float
    max_x: float
    max_y: float
    min_z: Optional[float] = None
    max_z: Optional[float] = None

    @staticmethod
    def from_points_2d(pts: List[List[float]]) -> Optional["BoundingBox"]:
        if not pts:
            return None
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        return BoundingBox(min(xs), min(ys), max(xs), max(ys))

    def merge(self, other: "BoundingBox") -> "BoundingBox":
        min_z = None
        if self.min_z is not None and other.min_z is not None:
            min_z = min(self.min_z, other.min_z)
        elif self.min_z is not None:
            min_z = self.min_z
        else:
            min_z = other.min_z

        max_z = None
        if self.max_z is not None and other.max_z is not None:
            max_z = max(self.max_z, other.max_z)
        elif self.max_z is not None:
            max_z = self.max_z
        else:
            max_z = other.max_z

        return BoundingBox(
            min(self.min_x, other.min_x),
            min(self.min_y, other.min_y),
            max(self.max_x, other.max_x),
            max(self.max_y, other.max_y),
            min_z,
            max_z,
        )


@dataclass
class CoordinateSystemHint:
    crs_type: str
    epsg_hint: Optional[int]
    affine_matrix: Optional[List[float]]
    units: str
    provenance: Optional[Provenance] = None


@dataclass
class Geometry:
    type: str
    data: Dict[str, Any]

    def bounding_box(self) -> Optional[BoundingBox]:
        t = self.type
        d = self.data
        if t == "Point":
            c = d["coord"]
            z = d.get("z")
            return BoundingBox(c[0], c[1], c[0], c[1], z, z)
        if t in ("MultiPoint", "LineString"):
            return BoundingBox.from_points_2d(d["coords"])
        if t == "CubicBezier":
            return BoundingBox.from_points_2d(d["control_points"])
        if t == "MultiLineString":
            flat = [pt for line in d["lines"] for pt in line]
            return BoundingBox.from_points_2d(flat)
        if t == "Polygon":
            flat = [pt for ring in d["rings"] for pt in ring]
            return BoundingBox.from_points_2d(flat)
        if t == "MultiPolygon":
            flat = [pt for poly in d["polygons"] for ring in poly for pt in ring]
            return BoundingBox.from_points_2d(flat)
        if t == "RegularGrid":
            ox, oy = d["origin"]
            sx, sy = d["spacing"]
            cols, rows = d["dims"]
            mx = ox + sx * max(0, cols - 1)
            my = oy + sy * max(0, rows - 1)
            return BoundingBox(min(ox, mx), min(oy, my), max(ox, mx), max(oy, my))
        if t == "SimpleMesh":
            verts = d.get("vertices", [])
            if not verts:
                return None
            xs = [v[0] for v in verts]
            ys = [v[1] for v in verts]
            zs = [v[2] for v in verts]
            return BoundingBox(min(xs), min(ys), max(xs), max(ys), min(zs), max(zs))
        return None

    def vertex_count(self) -> int:
        t = self.type
        d = self.data
        if t == "Point":
            return 1
        if t in ("MultiPoint", "LineString"):
            return len(d["coords"])
        if t == "CubicBezier":
            return len(d["control_points"])
        if t == "MultiLineString":
            return sum(len(l) for l in d["lines"])
        if t == "Polygon":
            return sum(len(r) for r in d["rings"])
        if t == "MultiPolygon":
            return sum(len(r) for p in d["polygons"] for r in p)
        if t == "RegularGrid":
            return int(d["dims"][0]) * int(d["dims"][1])
        if t == "SimpleMesh":
            return len(d.get("vertices", []))
        return 0


@dataclass
class GeometricFeature:
    id: str
    layer_id: str
    geometry: Geometry
    bbox: Optional[BoundingBox]
    properties: Dict[str, Any]
    provenance: Provenance


@dataclass
class Layer:
    id: str
    name: str
    style_stroke: str
    style_fill: str
    features: List[GeometricFeature]
    bbox: Optional[BoundingBox] = None


@dataclass
class ColumnSchema:
    name: str
    data_type: str
    byte_offset_in_record: int
    byte_width: int


@dataclass
class AttributeTable:
    id: str
    name: str
    record_stride: int
    record_count: int
    columns: List[ColumnSchema]
    rows: List[Dict[str, Any]]
    provenance: Provenance


@dataclass
class RasterTile:
    id: str
    width: int
    height: int
    channels: int
    bit_depth: int
    format: str
    georef_bbox: Optional[BoundingBox]
    exported_path: Optional[str]
    provenance: Provenance
    data: bytes = field(default=b"", repr=False)


@dataclass
class EmbeddedAsset:
    id: str
    kind: str
    description: str
    entropy: float
    is_opaque: bool
    metadata: Dict[str, Any]
    provenance: Provenance


@dataclass
class EntropyWindow:
    offset: int
    length: int
    shannon_entropy: float
    classification: str


@dataclass
class DocumentMetadata:
    source_filename: str
    file_size: int
    sha256: str
    detected_magic: str
    format_family: str
    overall_entropy: float
    endianness_hint: str
    tool_version: str = TOOL_VERSION


@dataclass
class DecoupledDocument:
    metadata: DocumentMetadata
    coordinate_system: CoordinateSystemHint
    global_bbox: Optional[BoundingBox]
    entropy_profile: List[EntropyWindow]
    decompressed_streams: List[DecompressedStreamInfo]
    layers: List[Layer]
    attribute_tables: List[AttributeTable]
    raster_tiles: List[RasterTile]
    embedded_assets: List[EmbeddedAsset]

    def recompute_global_bbox(self) -> None:
        global_bb: Optional[BoundingBox] = None
        for layer in self.layers:
            layer_bb: Optional[BoundingBox] = None
            for feat in layer.features:
                if feat.bbox is None:
                    feat.bbox = feat.geometry.bounding_box()
                if feat.bbox is not None:
                    layer_bb = feat.bbox if layer_bb is None else layer_bb.merge(feat.bbox)
            layer.bbox = layer_bb
            if layer_bb is not None:
                global_bb = layer_bb if global_bb is None else global_bb.merge(layer_bb)
        self.global_bbox = global_bb

    def total_features(self) -> int:
        return sum(len(l.features) for l in self.layers)

    def to_dict(self) -> Dict[str, Any]:
        raw = dataclasses.asdict(self)
        for tile in raw.get("raster_tiles", []):
            tile.pop("data", None)
        return raw


# ==============================================================================
# 2. SCORING & ENTROPY ENGINE
# ==============================================================================

def shannon_entropy(data: bytes | memoryview) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def score_entropy_for_structure(entropy: float) -> float:
    if entropy < 0.2:
        return 0.15
    if 2.0 <= entropy <= 6.6:
        return 0.95
    if entropy > 7.5:
        return 0.10
    return 0.65


def score_coordinate_sequence_2d(pts: List[List[float]]) -> Tuple[float, List[str]]:
    notes: List[str] = []
    if len(pts) < 2:
        return 0.0, ["Too few points"]

    min_x = float("inf")
    min_y = float("inf")
    max_x = float("-inf")
    max_y = float("-inf")

    for x, y in pts:
        if not (math.isfinite(x) and math.isfinite(y)):
            return 0.0, ["Contains non-finite IEEE-754 values"]
        ax, ay = abs(x), abs(y)
        if ax > 1.0e9 or ay > 1.0e9:
            return 0.0, ["Coordinate magnitude exceeds 1e9"]
        if (0.0 < ax < 1.0e-7) or (0.0 < ay < 1.0e-7):
            return 0.0, ["Contains subnormal/microscopic float noise"]
        min_x = min(min_x, x)
        min_y = min(min_y, y)
        max_x = max(max_x, x)
        max_y = max(max_y, y)

    dx = max_x - min_x
    dy = max_y - min_y
    diag = math.hypot(dx, dy)
    if diag < 1.0e-5:
        return 0.0, ["Degenerate zero-span bounding box"]

    aspect = max(dx / dy, dy / dx) if (dx > 1e-6 and dy > 1e-6) else 1.0
    if aspect > 10000.0:
        return 0.2, [f"Extreme aspect ratio ({aspect:.1f})"]

    steps: List[float] = []
    zero_steps = 0
    for i in range(len(pts) - 1):
        d = math.hypot(pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1])
        if d < 1.0e-9:
            zero_steps += 1
        steps.append(d)

    if zero_steps * 2 >= len(pts):
        return 0.1, ["Over 50% duplicate consecutive vertices"]

    mean_step = sum(steps) / len(steps)
    max_step = max(steps)
    ratio = mean_step / diag

    score = 0.70
    if ratio < 0.45:
        score += 0.15
        notes.append(f"Smooth spatial continuity (mean_step/diag = {ratio:.3f})")
    if max_step < diag * 0.85:
        score += 0.10
        notes.append("No extreme erratic jumps across bounding box")

    close_dist = math.hypot(pts[0][0] - pts[-1][0], pts[0][1] - pts[-1][1])
    if len(pts) >= 4 and close_dist <= 1.0e-4 * diag:
        score += 0.05
        notes.append("Forms closed polygon ring")

    if -180.0 <= min_x and max_x <= 180.0 and -90.0 <= min_y and max_y <= 90.0:
        notes.append("Bounds match geographic Lon/Lat domain")
    elif -1.0e7 <= min_x and max_x <= 1.0e7 and -1.0e7 <= min_y and max_y <= 1.0e7:
        notes.append("Bounds match plausible Cartesian/Projected domain")

    return min(1.0, max(0.0, score)), notes


def build_confidence(
    internal_consistency: float,
    pointer_validity: float,
    region_bytes: bytes | memoryview,
    geometric_plausibility: float,
    notes: List[str],
) -> ConfidenceBreakdown:
    ent = shannon_entropy(region_bytes)
    ent_score = score_entropy_for_structure(ent)
    all_notes = list(notes) + [f"Region Shannon entropy = {ent:.3f} bits/byte"]
    return ConfidenceBreakdown.compute(
        internal_consistency,
        pointer_validity,
        ent_score,
        geometric_plausibility,
        all_notes,
    )


# ==============================================================================
# 3. BOUNDED RECURSIVE STREAM CARVER & DECOMPRESSOR
# ==============================================================================

@dataclass
class CarvedStream:
    info: DecompressedStreamInfo
    host_root_span: ByteSpan
    data: bytes


CODEC_SHORT_TAG: Dict[str, str] = {
    "ZLIB_RFC1950": "zlib",
    "GZIP_RFC1952": "gzip",
    "RAW_DEFLATE": "raw",
}


def is_zlib_header(b0: int, b1: int, aggressive: bool = False) -> bool:
    """
    Identifies RFC 1950 zlib headers:
      - Standard common headers: 0x78 0x01, 0x78 0x5E, 0x78 0x9C, 0x78 0xDA.
      - In aggressive mode, also accepts any 0x78 followed by a byte without preset
        dictionary (FDICT bit 5 == 0) that satisfies the CMF/FLG modulo-31 check.
    """
    if b0 != 0x78:
        return False
    if b1 in (0x01, 0x5E, 0x9C, 0xDA):
        return True
    if aggressive:
        fdict = (b1 & 0x20) != 0
        fcheck_ok = ((b0 << 8) | b1) % 31 == 0
        return (not fdict) and fcheck_ok
    return False


def try_bounded_decompress(
    comp_slice: bytes, codec: str
) -> Tuple[Optional[bytes], int, Optional[str], Optional[str]]:
    """
    Streaming decompression using `zlib.decompressobj` with `max_length = 64 MB + 1`:
      - ZLIB_RFC1950: wbits = 15
      - GZIP_RFC1952: wbits = 31 (15 + 16)
      - RAW_DEFLATE : wbits = -15
    Returns `(decompressed_bytes, consumed_compressed_bytes, error_category, error_message)`
    where `error_category` distinguishes `HEADER_OK_CHECKSUM_MISMATCH` (Adler-32 / CRC-32 failure)
    from `INVALID_COMPRESSED_STREAM` and `DECOMPRESSION_BOMB_CAP_EXCEEDED`.
    """
    wbits_map = {
        "ZLIB_RFC1950": 15,
        "GZIP_RFC1952": 31,
        "RAW_DEFLATE": -15,
    }
    wbits = wbits_map[codec]
    try:
        dobj = zlib.decompressobj(wbits)
        out = dobj.decompress(comp_slice, MAX_DECOMPRESSED_BYTES + 1)
        if len(out) > MAX_DECOMPRESSED_BYTES or dobj.unconsumed_tail:
            return (
                None,
                0,
                "DECOMPRESSION_BOMB_CAP_EXCEEDED",
                f"Decompressed payload exceeds 64 MB hard cap ({MAX_DECOMPRESSED_BYTES} bytes)",
            )
        out += dobj.flush()
        if len(out) > MAX_DECOMPRESSED_BYTES:
            return (
                None,
                0,
                "DECOMPRESSION_BOMB_CAP_EXCEEDED",
                f"Decompressed payload exceeds 64 MB hard cap ({MAX_DECOMPRESSED_BYTES} bytes)",
            )
        if not dobj.eof:
            return (
                None,
                0,
                "INVALID_COMPRESSED_STREAM",
                "Incomplete or truncated compressed stream (EOF not reached)",
            )
        consumed = len(comp_slice) - len(dobj.unused_data)
        return out, max(1, consumed), None, None
    except zlib.error as exc:
        msg = str(exc)
        lower = msg.lower()
        if (
            "Error -3" in msg and ("incorrect data check" in lower or "incorrect length check" in lower)
        ) or "checksum" in lower or "crc" in lower:
            return None, 0, "HEADER_OK_CHECKSUM_MISMATCH", msg
        return None, 0, "INVALID_COMPRESSED_STREAM", msg
    except Exception as exc:
        return None, 0, "INVALID_COMPRESSED_STREAM", str(exc)


def carve_compressed_streams(
    root_data: bytes,
    cfg: Optional[CarverConfig] = None,
    verbose: bool = False,
) -> Tuple[List[CarvedStream], List[Tuple[int, int]]]:
    """
    Recursively carves and decompresses `zlib` (0x78 0x01 / 0x78 0x5E / 0x78 0x9C / 0x78 0xDA),
    `gzip` (0x1F 0x8B), and length-prefixed `raw Deflate` chunks in high-entropy (>= cfg.deflate_entropy_threshold)
    regions up to `cfg.max_recursion_depth` while enforcing 64 MB and 200:1 decompression bomb limits.
    """
    if cfg is None:
        cfg = CarverConfig(verbose=verbose)
    elif verbose:
        cfg.verbose = True

    carved_streams: List[CarvedStream] = []
    root_claimed_spans: List[Tuple[int, int]] = []

    def _register_child(
        decomp_bytes: bytes,
        codec: str,
        stream_off: int,
        actual_comp_len: int,
        claim_start: int,
        claim_len: int,
        parent_lineage: str,
        depth: int,
        local_idx: int,
        root_span_override: Optional[ByteSpan],
    ) -> None:
        short_tag = CODEC_SHORT_TAG.get(codec, "comp")
        if parent_lineage == "root":
            stream_id = f"parent_offset:0x{stream_off:x}/decompressed_{local_idx}_{short_tag}"
        else:
            stream_id = (
                f"{parent_lineage}/parent_offset:0x{stream_off:x}/decompressed_{local_idx}_{short_tag}"
            )

        host_span = root_span_override or ByteSpan(claim_start, claim_len)
        if depth == 1:
            root_claimed_spans.append((claim_start, claim_start + claim_len))

        ratio = len(decomp_bytes) / max(1, actual_comp_len)
        info = DecompressedStreamInfo(
            stream_id=stream_id,
            parent_lineage=parent_lineage,
            depth=depth,
            codec=codec,
            host_offset=stream_off,
            compressed_length=actual_comp_len,
            decompressed_length=len(decomp_bytes),
            expansion_ratio=round(ratio, 2),
            sha256=hashlib.sha256(decomp_bytes).hexdigest(),
        )

        if cfg.verbose:
            print(
                f"[carver] Unpacked {info.codec} stream '{info.stream_id}' "
                f"(depth={info.depth}, {info.compressed_length} B -> {info.decompressed_length} B, ratio={info.expansion_ratio:.2f}:1)"
            )

        carved_streams.append(
            CarvedStream(
                info=info,
                host_root_span=host_span,
                data=decomp_bytes,
            )
        )

        # Immediately feed child buffer into the recursive carver (respecting `cfg.max_recursion_depth`)
        _carve_recursive(decomp_bytes, stream_id, depth + 1, host_span)

    def _carve_recursive(
        buf: bytes,
        parent_lineage: str,
        depth: int,
        root_span_override: Optional[ByteSpan],
    ) -> None:
        if depth > cfg.max_recursion_depth or len(buf) < 10:
            return

        local_idx = 0
        i = 0
        n = len(buf)
        step = max(4, cfg.scan_step)
        consumed_intervals: List[Tuple[int, int]] = []

        def _is_consumed(off: int) -> bool:
            for s, e in consumed_intervals:
                if s <= off < e:
                    return True
            return False

        while i + 8 <= n:
            if _is_consumed(i):
                i += 1
                continue

            b0 = buf[i]
            b1 = buf[i + 1]

            # 1. Magic Header Detection: zlib (0x78 0x01, 0x78 0x5E, 0x78 0x9C, 0x78 0xDA)
            if is_zlib_header(b0, b1, cfg.aggressive):
                decomp_bytes, consumed_len, err_cat, err_msg = try_bounded_decompress(
                    buf[i:], "ZLIB_RFC1950"
                )
                if err_cat is not None:
                    if cfg.verbose:
                        print(
                            f"[carver-debug] Discarded candidate ZLIB_RFC1950 at 0x{i:x} "
                            f"(lineage={parent_lineage}, reason={err_cat}): {err_msg}",
                            file=sys.stderr,
                        )
                elif decomp_bytes is not None and len(decomp_bytes) >= 16:
                    actual_comp = max(1, consumed_len)
                    ratio = len(decomp_bytes) / actual_comp
                    if ratio > MAX_EXPANSION_RATIO:
                        if cfg.verbose:
                            print(
                                f"[carver-warn] Aborted ZLIB_RFC1950 stream at 0x{i:x} (lineage={parent_lineage}): "
                                f"expansion ratio {ratio:.1f}:1 exceeds {MAX_EXPANSION_RATIO:.0f}:1 limit",
                                file=sys.stderr,
                            )
                    else:
                        end_off = i + actual_comp
                        consumed_intervals.append((i, end_off))
                        _register_child(
                            decomp_bytes,
                            "ZLIB_RFC1950",
                            i,
                            actual_comp,
                            i,
                            actual_comp,
                            parent_lineage,
                            depth,
                            local_idx,
                            root_span_override,
                        )
                        local_idx += 1
                        i = end_off
                        continue

            # 2. Magic Header Detection: gzip (0x1F 0x8B 0x08 [flags <= 0x1F])
            elif (
                b0 == 0x1F
                and b1 == 0x8B
                and i + 10 <= n
                and buf[i + 2] == 0x08
                and buf[i + 3] <= 0x1F
            ):
                decomp_bytes, consumed_len, err_cat, err_msg = try_bounded_decompress(
                    buf[i:], "GZIP_RFC1952"
                )
                if err_cat is not None:
                    if cfg.verbose:
                        print(
                            f"[carver-debug] Discarded candidate GZIP_RFC1952 at 0x{i:x} "
                            f"(lineage={parent_lineage}, reason={err_cat}): {err_msg}",
                            file=sys.stderr,
                        )
                elif decomp_bytes is not None and len(decomp_bytes) >= 16:
                    actual_comp = max(1, consumed_len)
                    ratio = len(decomp_bytes) / actual_comp
                    if ratio > MAX_EXPANSION_RATIO:
                        if cfg.verbose:
                            print(
                                f"[carver-warn] Aborted GZIP_RFC1952 stream at 0x{i:x} (lineage={parent_lineage}): "
                                f"expansion ratio {ratio:.1f}:1 exceeds {MAX_EXPANSION_RATIO:.0f}:1 limit",
                                file=sys.stderr,
                            )
                    else:
                        end_off = i + actual_comp
                        consumed_intervals.append((i, end_off))
                        _register_child(
                            decomp_bytes,
                            "GZIP_RFC1952",
                            i,
                            actual_comp,
                            i,
                            actual_comp,
                            parent_lineage,
                            depth,
                            local_idx,
                            root_span_override,
                        )
                        local_idx += 1
                        i = end_off
                        continue

            # 3. Sliding-window coarse-step high-entropy check (>= cfg.deflate_entropy_threshold)
            #    followed by local 4-byte refinement and strengthened LE/BE 4-byte length-prefix verification.
            if i >= 4 and i + cfg.min_high_entropy_run <= n:
                last_end = consumed_intervals[-1][1] if consumed_intervals else 0
                should_probe = (i % step == 0) or (i == ((last_end + 3) & ~3)) or (i == ((last_end + 7) & ~3))
                if should_probe:
                    win_end = min(n, i + 512)
                    if shannon_entropy(buf[i:win_end]) >= cfg.deflate_entropy_threshold:
                        refine_start = max(4, i - step)
                        refine_end = min(n - cfg.min_high_entropy_run, i + step)
                        unpacked_end: Optional[int] = None

                        for r_off in range(refine_start, refine_end + 1):
                            if _is_consumed(r_off) or _is_consumed(r_off - 4):
                                continue
                            rem = n - r_off
                            val_le = struct.unpack("<I", buf[r_off - 4 : r_off])[0]
                            val_be = struct.unpack(">I", buf[r_off - 4 : r_off])[0]
                            le_ok = 16 <= val_le <= min(MAX_DECOMPRESSED_BYTES, rem * 200)
                            be_ok = 16 <= val_be <= min(MAX_DECOMPRESSED_BYTES, rem * 200)
                            if not (le_ok or be_ok):
                                continue

                            sample_len = max(
                                cfg.min_high_entropy_run,
                                min(rem, max(val_le if le_ok else 0, val_be if be_ok else 0, 512)),
                            )
                            if shannon_entropy(buf[r_off : r_off + sample_len]) < cfg.deflate_entropy_threshold:
                                continue

                            decomp_bytes, consumed_len, err_cat, err_msg = try_bounded_decompress(
                                buf[r_off:], "RAW_DEFLATE"
                            )
                            if err_cat is not None:
                                if cfg.verbose:
                                    print(
                                        f"[carver-debug] Discarded candidate RAW_DEFLATE at 0x{r_off:x} "
                                        f"(lineage={parent_lineage}, reason={err_cat}): {err_msg}",
                                        file=sys.stderr,
                                    )
                                continue
                            if decomp_bytes is None or len(decomp_bytes) < 16:
                                continue

                            actual_comp = max(1, consumed_len)
                            actual_decomp = len(decomp_bytes)
                            ratio = actual_decomp / actual_comp
                            if ratio > MAX_EXPANSION_RATIO:
                                continue

                            # Check both LE and BE 4-byte prefixes against decompressed length AND compressed length
                            # (must be within 20% or exact match), preferring whichever endianness matches closer.
                            def _prefix_error(pval: int) -> Optional[float]:
                                if not (16 <= pval <= MAX_DECOMPRESSED_BYTES):
                                    return None
                                err_d = abs(actual_decomp - pval) / pval
                                err_c = (abs(actual_comp - pval) / pval) if pval <= rem else float("inf")
                                best = min(err_d, err_c)
                                return best if best <= 0.20 else None

                            err_le = _prefix_error(val_le)
                            err_be = _prefix_error(val_be)

                            best_match: Optional[Tuple[int, str, float]] = None
                            if err_le is not None and err_be is not None:
                                best_match = (
                                    (val_le, "LE", err_le)
                                    if err_le <= err_be
                                    else (val_be, "BE", err_be)
                                )
                            elif err_le is not None:
                                best_match = (val_le, "LE", err_le)
                            elif err_be is not None:
                                best_match = (val_be, "BE", err_be)

                            if best_match is not None:
                                matched_len, endian_tag, rel_err = best_match
                                if cfg.verbose:
                                    print(
                                        f"[carver] Raw Deflate at 0x{r_off:x} matched 4-byte {endian_tag} "
                                        f"length prefix {matched_len} (rel_err={rel_err * 100.0:.1f}%)"
                                    )
                                claim_start = r_off - 4
                                claim_len = actual_comp + 4
                                end_off = r_off + actual_comp
                                consumed_intervals.append((claim_start, end_off))
                                _register_child(
                                    decomp_bytes,
                                    "RAW_DEFLATE",
                                    r_off,
                                    actual_comp,
                                    claim_start,
                                    claim_len,
                                    parent_lineage,
                                    depth,
                                    local_idx,
                                    root_span_override,
                                )
                                local_idx += 1
                                unpacked_end = end_off
                                break

                        if unpacked_end is not None:
                            i = unpacked_end
                            continue
                    i += 1
                    continue

            i += 1

    _carve_recursive(root_data, "root", 1, None)
    return carved_streams, root_claimed_spans


# ==============================================================================
# 4. BINARY STRUCTURAL SCANNER & PATTERN RECOGNITION ENGINE
# ==============================================================================

class ClaimTracker:
    def __init__(self) -> None:
        self.claimed: List[Tuple[int, int]] = []

    def is_claimed(self, offset: int, length: int) -> bool:
        end = offset + length
        for s, e in self.claimed:
            if offset < e and end > s:
                return True
        return False

    def claim(self, offset: int, length: int) -> None:
        self.claimed.append((offset, offset + length))


def identify_magic(data: bytes) -> Tuple[str, str]:
    if len(data) >= 4:
        if data[:4] == b"OADC":
            return ("OADC (OpenArchive Vector Container)", "LEGACY_CAD_GIS_CONTAINER")
        code = struct.unpack(">I", data[:4])[0]
        if code == 9994 and len(data) >= 100:
            return ("0x0000270A (Esri Shapefile Main Header)", "ESRI_SHAPEFILE")
        if data[:4] == b"AC10":
            return ("AC10xx (AutoCAD DWG Archive)", "AUTOCAD_DWG")
        if data[:2] == b"\x1f\x8b":
            return ("GZIP Compressed Archive (RFC 1952)", "COMPRESSED_CONTAINER")
        if data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
            return ("ZLIB Compressed Stream (RFC 1950)", "COMPRESSED_CONTAINER")
        if data[:4] in (b"II*\x00", b"MM\x00*"):
            return ("TIFF / GeoTIFF / RAW Container", "TIFF_CONTAINER")
        if data[:4] == b"\x89PNG":
            return ("PNG Image", "RASTER_IMAGE")
    prefix = data[: min(8, len(data))].hex()
    return (f"UNKNOWN (0x{prefix})", "GENERIC_STRUCTURED_BINARY")


def compute_entropy_profile(data: bytes, window_size: int = 256) -> List[EntropyWindow]:
    profile: List[EntropyWindow] = []
    step = max(64, window_size)
    offset = 0
    n = len(data)
    while offset < n:
        end = min(n, offset + step)
        chunk = data[offset:end]
        ent = shannon_entropy(chunk)
        if ent >= 7.45 and len(chunk) >= 64:
            cls = "HIGH_COMPRESSED_OR_OPAQUE"
        elif ent >= 2.0:
            cls = "MEDIUM_MIXED"
        else:
            cls = "LOW_STRUCTURED"
        profile.append(EntropyWindow(offset, end - offset, ent, cls))
        offset += step
    return profile


def scan_binary(
    filename: str,
    data: bytes,
    min_confidence: float = 0.60,
    entropy_window_size: int = 256,
    carver_cfg: Optional[CarverConfig] = None,
    verbose: bool = False,
) -> DecoupledDocument:
    sha256 = hashlib.sha256(data).hexdigest()
    detected_magic, format_family = identify_magic(data)
    overall_entropy = shannon_entropy(data)
    entropy_profile = compute_entropy_profile(data, entropy_window_size)

    layers: List[Layer] = []
    attribute_tables: List[AttributeTable] = []
    raster_tiles: List[RasterTile] = []
    embedded_assets: List[EmbeddedAsset] = []
    crs_hint = CoordinateSystemHint(
        crs_type="LOCAL_CARTESIAN",
        epsg_hint=None,
        affine_matrix=None,
        units="units",
        provenance=None,
    )

    # Step 1: Bounded Recursive Stream Carver & Decompressor
    carved_streams, root_carved_spans = carve_compressed_streams(
        data, cfg=carver_cfg, verbose=verbose
    )
    decompressed_streams = [c.info for c in carved_streams]

    # Step 2: Scan the host ("root") binary
    host_tracker = ClaimTracker()
    for s, e in root_carved_spans:
        host_tracker.claim(s, max(0, e - s))

    _scan_single_stream(
        data=data,
        stream_lineage="root",
        host_compressed_span=None,
        tracker=host_tracker,
        layers=layers,
        attribute_tables=attribute_tables,
        raster_tiles=raster_tiles,
        embedded_assets=embedded_assets,
        crs_hint=crs_hint,
        is_root=True,
        entropy_profile=entropy_profile,
    )

    # Step 3: Pass-Through Pipeline — scan every decompressed child buffer
    for carved in carved_streams:
        child_tracker = ClaimTracker()
        child_entropy = compute_entropy_profile(carved.data, entropy_window_size)
        _scan_single_stream(
            data=carved.data,
            stream_lineage=carved.info.stream_id,
            host_compressed_span=carved.host_root_span,
            tracker=child_tracker,
            layers=layers,
            attribute_tables=attribute_tables,
            raster_tiles=raster_tiles,
            embedded_assets=embedded_assets,
            crs_hint=crs_hint,
            is_root=False,
            entropy_profile=child_entropy,
        )

    # Filter by minimum confidence threshold
    for layer in layers:
        layer.features = [
            f for f in layer.features if f.provenance.confidence.composite >= min_confidence
        ]
    layers = [l for l in layers if l.features]
    attribute_tables = [
        t for t in attribute_tables if t.provenance.confidence.composite >= min_confidence
    ]
    raster_tiles = [
        r for r in raster_tiles if r.provenance.confidence.composite >= min_confidence
    ]
    embedded_assets = [
        a
        for a in embedded_assets
        if a.is_opaque or a.provenance.confidence.composite >= min_confidence
    ]

    doc = DecoupledDocument(
        metadata=DocumentMetadata(
            source_filename=filename,
            file_size=len(data),
            sha256=sha256,
            detected_magic=detected_magic,
            format_family=format_family,
            overall_entropy=overall_entropy,
            endianness_hint="LITTLE_ENDIAN",
        ),
        coordinate_system=crs_hint,
        global_bbox=None,
        entropy_profile=entropy_profile,
        decompressed_streams=decompressed_streams,
        layers=layers,
        attribute_tables=attribute_tables,
        raster_tiles=raster_tiles,
        embedded_assets=embedded_assets,
    )
    doc.recompute_global_bbox()
    return doc


def _scan_single_stream(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    layers: List[Layer],
    attribute_tables: List[AttributeTable],
    raster_tiles: List[RasterTile],
    embedded_assets: List[EmbeddedAsset],
    crs_hint: CoordinateSystemHint,
    is_root: bool,
    entropy_profile: List[EntropyWindow],
) -> None:
    if len(data) >= 4 and data[:4] == b"OADC":
        _parse_oadc_container(
            data,
            stream_lineage,
            host_compressed_span,
            tracker,
            layers,
            attribute_tables,
            raster_tiles,
            embedded_assets,
            crs_hint,
        )
    elif len(data) >= 100 and struct.unpack(">I", data[:4])[0] == 9994:
        _parse_shapefile_records(
            data, stream_lineage, host_compressed_span, tracker, layers, crs_hint
        )

    scan_slice = data[: min(len(data), MAX_HEURISTIC_SCAN_BYTES)]
    _detect_offset_tables(scan_slice, stream_lineage, host_compressed_span, tracker, embedded_assets)
    _detect_embedded_rasters(scan_slice, stream_lineage, host_compressed_span, tracker, raster_tiles)
    _detect_coordinate_sequences(
        scan_slice, stream_lineage, host_compressed_span, tracker, layers, crs_hint
    )
    _detect_repeating_records(
        scan_slice, stream_lineage, host_compressed_span, tracker, attribute_tables
    )

    if is_root:
        _detect_opaque_regions(
            data, stream_lineage, host_compressed_span, entropy_profile, tracker, embedded_assets
        )


def _parse_oadc_container(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    layers: List[Layer],
    attribute_tables: List[AttributeTable],
    raster_tiles: List[RasterTile],
    embedded_assets: List[EmbeddedAsset],
    crs_hint: CoordinateSystemHint,
) -> None:
    if len(data) < 16:
        return
    version, section_count, dir_offset, _reserved = struct.unpack("<HHII", data[4:16])
    dir_bytes = section_count * 16
    if dir_offset + dir_bytes > len(data):
        return
    tracker.claim(0, 16)
    tracker.claim(dir_offset, dir_bytes)

    valid_ptrs = 0
    section_entries: List[Tuple[int, int, int, int, int]] = []
    for i in range(section_count):
        base = dir_offset + i * 16
        sec_type, sec_off, sec_len, sec_meta = struct.unpack("<IIII", data[base : base + 16])
        if 16 <= sec_off and sec_off + sec_len <= len(data):
            valid_ptrs += 1
            section_entries.append((i, sec_type, sec_off, sec_len, sec_meta))

    ptr_validity = valid_ptrs / section_count if section_count > 0 else 0.0
    dir_slice = data[dir_offset : dir_offset + dir_bytes]
    embedded_assets.append(
        EmbeddedAsset(
            id=f"asset_offset_dir_{len(embedded_assets)}",
            kind="OFFSET_TABLE",
            description=f"Validated section pointer directory ({section_count} entries, v{version})",
            entropy=shannon_entropy(dir_slice),
            is_opaque=False,
            metadata={
                "container_version": version,
                "section_count": section_count,
                "valid_pointers": valid_ptrs,
            },
            provenance=Provenance(
                id=f"prov_offset_dir_{len(embedded_assets)}",
                span=ByteSpan(dir_offset, dir_bytes),
                detector="PointerTableValidator",
                endianness="LITTLE_ENDIAN",
                stream_lineage=stream_lineage,
                host_compressed_span=host_compressed_span,
                confidence=build_confidence(
                    0.98,
                    ptr_validity,
                    dir_slice,
                    0.95,
                    [f"{valid_ptrs}/{section_count} section pointers resolve cleanly within stream bounds"],
                ),
            ),
        )
    )

    for idx, sec_type, sec_off, sec_len, sec_meta in section_entries:
        already_claimed = tracker.is_claimed(sec_off, sec_len)
        sec_slice = data[sec_off : sec_off + sec_len]
        tracker.claim(sec_off, sec_len)

        if sec_type == 1 and sec_len >= 52:
            mat = list(struct.unpack("<6d", sec_slice[:48]))
            epsg = struct.unpack("<I", sec_slice[48:52])[0]
            crs_hint.crs_type = "PROJECTED_OR_GEOGRAPHIC_EPSG" if epsg > 0 else "AFFINE_LOCAL_CAD"
            crs_hint.epsg_hint = epsg if epsg > 0 else None
            crs_hint.affine_matrix = mat
            crs_hint.units = "degrees" if epsg == 4326 else "meters"
            crs_hint.provenance = Provenance(
                id=f"prov_crs_{idx}",
                span=ByteSpan(sec_off, sec_len),
                detector="AffineCrsDetector",
                endianness="LITTLE_ENDIAN",
                stream_lineage=stream_lineage,
                host_compressed_span=host_compressed_span,
                confidence=build_confidence(
                    0.96,
                    1.0,
                    sec_slice,
                    0.95,
                    [f"Recovered 2D affine transform & EPSG={epsg}"],
                ),
            )

        elif sec_type == 2 and sec_len >= 24:
            raw_name = sec_slice[:16].split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
            layer_name = raw_name or f"layer_{idx}"
            geom_kind, feat_count, _pad = struct.unpack("<HHI", sec_slice[16:24])
            cursor = 24
            features: List[GeometricFeature] = []
            layer_id = f"layer_{len(layers)}_{idx}"

            for f_idx in range(feat_count):
                if cursor + 8 > sec_len:
                    break
                feat_start = sec_off + cursor
                feat_id_num, vtx_count = struct.unpack("<II", sec_slice[cursor : cursor + 8])
                cursor += 8
                byte_needed = vtx_count * 16
                if vtx_count == 0 or cursor + byte_needed > sec_len:
                    break
                pts: List[List[float]] = []
                for _ in range(vtx_count):
                    x, y = struct.unpack("<dd", sec_slice[cursor : cursor + 16])
                    pts.append([x, y])
                    cursor += 16
                feat_len = 8 + byte_needed

                if len(pts) == 1:
                    ok = math.isfinite(pts[0][0]) and math.isfinite(pts[0][1])
                    geom_score = 0.90 if ok else 0.0
                    notes = ["Single 2D point coordinate"]
                else:
                    geom_score, notes = score_coordinate_sequence_2d(pts)

                if geom_kind == 1 and len(pts) == 1:
                    geom = Geometry("Point", {"coord": pts[0], "z": None})
                elif geom_kind == 1:
                    geom = Geometry("MultiPoint", {"coords": pts})
                elif geom_kind == 2:
                    geom = Geometry("LineString", {"coords": pts})
                elif geom_kind == 3:
                    geom = Geometry("Polygon", {"rings": [pts]})
                elif geom_kind == 4:
                    geom = Geometry("CubicBezier", {"control_points": pts})
                else:
                    geom = Geometry("LineString", {"coords": pts})

                conf = build_confidence(
                    0.96,
                    ptr_validity,
                    data[feat_start : feat_start + feat_len],
                    geom_score,
                    notes,
                )
                features.append(
                    GeometricFeature(
                        id=f"feat_{idx}_{f_idx}",
                        layer_id=layer_id,
                        geometry=geom,
                        bbox=geom.bounding_box(),
                        properties={
                            "record_id": feat_id_num,
                            "layer": layer_name,
                            "stream_lineage": stream_lineage,
                        },
                        provenance=Provenance(
                            id=f"prov_feat_{idx}_{f_idx}",
                            span=ByteSpan(feat_start, feat_len),
                            detector="StructuredVectorSectionDetector",
                            endianness="LITTLE_ENDIAN",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=conf,
                        ),
                    )
                )

            stroke, fill = LAYER_PALETTE[len(layers) % len(LAYER_PALETTE)]
            layers.append(
                Layer(
                    id=layer_id,
                    name=layer_name,
                    style_stroke=stroke,
                    style_fill=fill,
                    features=features,
                )
            )

        elif sec_type == 3 and sec_len >= 24 and sec_len % 24 == 0:
            stride = 24
            count = sec_len // stride
            rows: List[Dict[str, Any]] = []
            for r in range(count):
                r_slice = sec_slice[r * stride : (r + 1) * stride]
                id_val, metric_val = struct.unpack("<If", r_slice[:8])
                label = r_slice[8:24].split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
                rows.append(
                    {
                        "record_id": id_val,
                        "measurement": round(float(metric_val), 4),
                        "label": label,
                    }
                )
            attribute_tables.append(
                AttributeTable(
                    id=f"table_{idx}",
                    name=f"recovered_attributes_{idx}",
                    record_stride=stride,
                    record_count=count,
                    columns=[
                        ColumnSchema("record_id", "UINT32", 0, 4),
                        ColumnSchema("measurement", "FLOAT32", 4, 4),
                        ColumnSchema("label", "ASCII_16", 8, 16),
                    ],
                    rows=rows,
                    provenance=Provenance(
                        id=f"prov_table_{idx}",
                        span=ByteSpan(sec_off, sec_len),
                        detector="RepeatingRecordDetector",
                        endianness="LITTLE_ENDIAN",
                        stream_lineage=stream_lineage,
                        host_compressed_span=host_compressed_span,
                        confidence=build_confidence(
                            0.95,
                            ptr_validity,
                            sec_slice,
                            0.90,
                            [f"Fixed stride = {stride} bytes across {count} records"],
                        ),
                    ),
                )
            )

        elif sec_type == 4 and sec_len >= 40:
            ox, oy, sx, sy, cols, rows_cnt = struct.unpack("<ddddII", sec_slice[:40])
            expected = 40 + cols * rows_cnt * 4
            if expected <= sec_len and cols > 1 and rows_cnt > 1:
                vals = [
                    round(float(v), 4)
                    for (v,) in struct.iter_unpack("<f", sec_slice[40:expected])
                ]
                geom = Geometry(
                    "RegularGrid",
                    {
                        "origin": [ox, oy],
                        "spacing": [sx, sy],
                        "dims": [cols, rows_cnt],
                        "values": vals,
                    },
                )
                stroke, fill = LAYER_PALETTE[len(layers) % len(LAYER_PALETTE)]
                layers.append(
                    Layer(
                        id=f"layer_grid_{idx}",
                        name=f"regular_grid_{idx}",
                        style_stroke=stroke,
                        style_fill=fill,
                        features=[
                            GeometricFeature(
                                id=f"feat_grid_{idx}",
                                layer_id=f"layer_grid_{idx}",
                                geometry=geom,
                                bbox=geom.bounding_box(),
                                properties={
                                    "grid_cols": cols,
                                    "grid_rows": rows_cnt,
                                    "stream_lineage": stream_lineage,
                                },
                                provenance=Provenance(
                                    id=f"prov_grid_{idx}",
                                    span=ByteSpan(sec_off, sec_len),
                                    detector="RegularGridDetector",
                                    endianness="LITTLE_ENDIAN",
                                    stream_lineage=stream_lineage,
                                    host_compressed_span=host_compressed_span,
                                    confidence=build_confidence(
                                        0.95,
                                        ptr_validity,
                                        sec_slice,
                                        0.94,
                                        [f"Regular {cols}x{rows_cnt} float32 lattice with spacing ({sx}, {sy})"],
                                    ),
                                ),
                            )
                        ],
                    )
                )

        elif sec_type == 5 and sec_len >= 48:
            width, height, channels = struct.unpack("<IIB", sec_slice[:9])
            min_x, min_y, max_x, max_y = struct.unpack("<dddd", sec_slice[16:48])
            pix_bytes = width * height * channels
            if 48 + pix_bytes <= sec_len and width > 0 and height > 0:
                raster_tiles.append(
                    RasterTile(
                        id=f"raster_tile_{idx}",
                        width=width,
                        height=height,
                        channels=channels,
                        bit_depth=8,
                        format="RAW_RGB8" if channels == 3 else "RAW_GRAY8",
                        georef_bbox=BoundingBox(min_x, min_y, max_x, max_y),
                        exported_path=None,
                        data=sec_slice[48 : 48 + pix_bytes],
                        provenance=Provenance(
                            id=f"prov_raster_{idx}",
                            span=ByteSpan(sec_off, sec_len),
                            detector="RasterTileDetector",
                            endianness="LITTLE_ENDIAN",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=build_confidence(
                                0.96,
                                ptr_validity,
                                sec_slice,
                                0.92,
                                [f"Recovered {width}x{height}x{channels} uncompressed raster tile"],
                            ),
                        ),
                    )
                )

        else:
            # If the carver already unpacked this section as a compressed stream, don't mark it opaque
            if not already_claimed:
                ent = shannon_entropy(sec_slice)
                embedded_assets.append(
                    EmbeddedAsset(
                        id=f"asset_opaque_{idx}",
                        kind="OPAQUE_COMPRESSED_OR_ENCRYPTED",
                        description=(
                            f"Opaque/encrypted payload block (entropy {ent:.2f} bits/byte); "
                            "preserved as-is without decryption attempt"
                        ),
                        entropy=ent,
                        is_opaque=True,
                        metadata={"section_type_tag": sec_type, "section_flags": sec_meta},
                        provenance=Provenance(
                            id=f"prov_opaque_{idx}",
                            span=ByteSpan(sec_off, sec_len),
                            detector="EntropyOpaqueClassifier",
                            endianness="UNKNOWN",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=ConfidenceBreakdown.compute(
                                0.95,
                                ptr_validity,
                                0.95,
                                0.85,
                                [f"High Shannon entropy ({ent:.3f} bits/byte) not matching standard Deflate/zlib/gzip streams"],
                            ),
                        ),
                    )
                )


def _parse_shapefile_records(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    layers: List[Layer],
    crs_hint: CoordinateSystemHint,
) -> None:
    if len(data) < 100:
        return
    tracker.claim(0, 100)
    min_x, min_y = struct.unpack("<dd", data[36:52])
    if -180.0 <= min_x <= 180.0 and -90.0 <= min_y <= 90.0:
        crs_hint.crs_type = "WGS84_LON_LAT"
        crs_hint.epsg_hint = 4326
        crs_hint.units = "degrees"

    cursor = 100
    features: List[GeometricFeature] = []
    while cursor + 12 <= len(data):
        rec_start = cursor
        rec_num, content_words = struct.unpack(">II", data[cursor : cursor + 8])
        content_bytes = content_words * 2
        if cursor + 8 + content_bytes > len(data) or content_bytes < 4:
            break
        rec_slice = data[cursor + 8 : cursor + 8 + content_bytes]
        shape_type = struct.unpack("<I", rec_slice[:4])[0]

        if shape_type == 1 and len(rec_slice) >= 20:
            x, y = struct.unpack("<dd", rec_slice[4:20])
            geom = Geometry("Point", {"coord": [x, y], "z": None})
            features.append(
                GeometricFeature(
                    id=f"shp_pt_{rec_num}",
                    layer_id="layer_shp_0",
                    geometry=geom,
                    bbox=geom.bounding_box(),
                    properties={"record_number": rec_num, "stream_lineage": stream_lineage},
                    provenance=Provenance(
                        id=f"prov_shp_{rec_num}",
                        span=ByteSpan(rec_start, 8 + content_bytes),
                        detector="ShapefileRecordDetector",
                        endianness="MIXED_BE_LE",
                        stream_lineage=stream_lineage,
                        host_compressed_span=host_compressed_span,
                        confidence=build_confidence(
                            0.98,
                            1.0,
                            data[rec_start : rec_start + 8 + content_bytes],
                            0.95,
                            ["Valid Esri Shapefile Point record"],
                        ),
                    ),
                )
            )
        elif shape_type in (3, 5) and len(rec_slice) >= 44:
            num_parts, num_points = struct.unpack("<II", rec_slice[36:44])
            parts_end = 44 + num_parts * 4
            pts_end = parts_end + num_points * 16
            if pts_end <= len(rec_slice) and num_points >= 2:
                parts = list(struct.unpack(f"<{num_parts}I", rec_slice[44:parts_end]))
                all_pts = [
                    [x, y]
                    for x, y in struct.iter_unpack("<dd", rec_slice[parts_end:pts_end])
                ]
                rings: List[List[List[float]]] = []
                for p_idx, start_i in enumerate(parts):
                    end_i = parts[p_idx + 1] if p_idx + 1 < len(parts) else num_points
                    if start_i < end_i <= len(all_pts):
                        rings.append(all_pts[start_i:end_i])
                g_score, notes = score_coordinate_sequence_2d(all_pts)
                if shape_type == 5:
                    geom = Geometry("Polygon", {"rings": rings})
                elif len(rings) == 1:
                    geom = Geometry("LineString", {"coords": rings[0]})
                else:
                    geom = Geometry("MultiLineString", {"lines": rings})

                features.append(
                    GeometricFeature(
                        id=f"shp_feat_{rec_num}",
                        layer_id="layer_shp_0",
                        geometry=geom,
                        bbox=geom.bounding_box(),
                        properties={"record_number": rec_num, "stream_lineage": stream_lineage},
                        provenance=Provenance(
                            id=f"prov_shp_{rec_num}",
                            span=ByteSpan(rec_start, 8 + content_bytes),
                            detector="ShapefileRecordDetector",
                            endianness="MIXED_BE_LE",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=build_confidence(
                                0.98,
                                1.0,
                                data[rec_start : rec_start + 8 + content_bytes],
                                g_score,
                                notes,
                            ),
                        ),
                    )
                )

        tracker.claim(rec_start, 8 + content_bytes)
        cursor += 8 + content_bytes

    if features:
        stroke, fill = LAYER_PALETTE[len(layers) % len(LAYER_PALETTE)]
        layers.append(
            Layer(
                id="layer_shp_0",
                name="shapefile_vectors",
                style_stroke=stroke,
                style_fill=fill,
                features=features,
            )
        )


def _detect_offset_tables(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    embedded_assets: List[EmbeddedAsset],
) -> None:
    n = len(data)
    if n < 32:
        return
    offset = 0
    while offset + 20 <= n:
        if tracker.is_claimed(offset, 20):
            offset += 4
            continue
        count = struct.unpack("<I", data[offset : offset + 4])[0]
        if 4 <= count <= 256 and offset + 4 + count * 4 <= n:
            ptrs = struct.unpack(f"<{count}I", data[offset + 4 : offset + 4 + count * 4])
            valid = True
            prev = 0
            for p in ptrs:
                if p <= prev or p >= n:
                    valid = False
                    break
                prev = p
            if valid:
                byte_len = 4 + count * 4
                tracker.claim(offset, byte_len)
                chunk = data[offset : offset + byte_len]
                embedded_assets.append(
                    EmbeddedAsset(
                        id=f"asset_ptrtab_{len(embedded_assets)}_0x{offset:x}",
                        kind="OFFSET_TABLE",
                        description=f"Monotonic u32 offset table ({count} valid stream pointers)",
                        entropy=shannon_entropy(chunk),
                        is_opaque=False,
                        metadata={"pointer_count": count, "pointers": list(ptrs)},
                        provenance=Provenance(
                            id=f"prov_ptrtab_{len(embedded_assets)}_0x{offset:x}",
                            span=ByteSpan(offset, byte_len),
                            detector="SlidingOffsetTableDetector",
                            endianness="LITTLE_ENDIAN",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=build_confidence(
                                0.92,
                                1.0,
                                chunk,
                                0.85,
                                [f"{count} strictly increasing offsets within stream size {n}"],
                            ),
                        ),
                    )
                )
                offset += byte_len
                continue
        offset += 4


def _detect_embedded_rasters(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    raster_tiles: List[RasterTile],
) -> None:
    png_sig = b"\x89PNG\r\n\x1a\n"
    iend_sig = b"IEND"
    n = len(data)
    if n < 32:
        return
    i = 0
    while i + 32 <= n:
        if not tracker.is_claimed(i, 16) and data[i : i + 8] == png_sig:
            end_pos = data.find(iend_sig, i + 8)
            if end_pos != -1:
                total_len = min(n - i, (end_pos - i) + 8)
                width, height, bit_depth = struct.unpack(">IIB", data[i + 16 : i + 25])
                tracker.claim(i, total_len)
                raster_tiles.append(
                    RasterTile(
                        id=f"raster_png_0x{i:x}",
                        width=width,
                        height=height,
                        channels=4,
                        bit_depth=bit_depth,
                        format="EMBEDDED_PNG",
                        georef_bbox=None,
                        exported_path=None,
                        data=data[i : i + total_len],
                        provenance=Provenance(
                            id=f"prov_png_0x{i:x}",
                            span=ByteSpan(i, total_len),
                            detector="EmbeddedPngSignatureDetector",
                            endianness="BIG_ENDIAN",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=build_confidence(
                                0.99,
                                1.0,
                                data[i : i + total_len],
                                0.95,
                                [f"Embedded PNG stream ({width}x{height}, {total_len} bytes)"],
                            ),
                        ),
                    )
                )
                i += total_len
                continue
        i += 1


def _detect_coordinate_sequences(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    layers: List[Layer],
    crs_hint: CoordinateSystemHint,
) -> None:
    n = len(data)
    if n < 48:
        return
    features: List[GeometricFeature] = []
    offset = 0
    layer_id = (
        "layer_heuristic_f64"
        if stream_lineage == "root"
        else f"layer_decompressed_{len(layers)}"
    )

    while offset + 36 <= n:
        if tracker.is_claimed(offset, 36):
            offset += 4
            continue

        maybe_count = struct.unpack("<I", data[offset : offset + 4])[0]
        if 3 <= maybe_count <= 10000:
            byte_len = 4 + maybe_count * 16
            if offset + byte_len <= n and not tracker.is_claimed(offset, byte_len):
                pts = [
                    [x, y]
                    for x, y in struct.iter_unpack(
                        "<dd", data[offset + 4 : offset + byte_len]
                    )
                ]
                geom_score, notes = score_coordinate_sequence_2d(pts)
                if geom_score >= 0.65:
                    tracker.claim(offset, byte_len)
                    closed = (
                        len(pts) >= 4
                        and math.hypot(pts[0][0] - pts[-1][0], pts[0][1] - pts[-1][1]) < 1e-4
                    )
                    geom = (
                        Geometry("Polygon", {"rings": [pts]})
                        if closed
                        else Geometry("LineString", {"coords": pts})
                    )
                    bb = geom.bounding_box()
                    if (
                        bb
                        and -180.0 <= bb.min_x
                        and bb.max_x <= 180.0
                        and -90.0 <= bb.min_y
                        and bb.max_y <= 90.0
                    ):
                        crs_hint.crs_type = "WGS84_LON_LAT"
                        crs_hint.epsg_hint = 4326
                        crs_hint.units = "degrees"

                    features.append(
                        GeometricFeature(
                            id=f"feat_f64_{len(layers)}_0x{offset:x}",
                            layer_id=layer_id,
                            geometry=geom,
                            bbox=bb,
                            properties={
                                "vertex_count": maybe_count,
                                "encoding": "LENGTH_PREFIXED_F64_LE",
                                "stream_lineage": stream_lineage,
                            },
                            provenance=Provenance(
                                id=f"prov_f64_{len(layers)}_0x{offset:x}",
                                span=ByteSpan(offset, byte_len),
                                detector="SlidingWindowFloat64Detector",
                                endianness="LITTLE_ENDIAN",
                                stream_lineage=stream_lineage,
                                host_compressed_span=host_compressed_span,
                                confidence=build_confidence(
                                    0.92,
                                    0.85,
                                    data[offset : offset + byte_len],
                                    geom_score,
                                    notes,
                                ),
                            ),
                        )
                    )
                    offset += byte_len
                    continue

            byte_len_f32 = 4 + maybe_count * 8
            if offset + byte_len_f32 <= n and not tracker.is_claimed(offset, byte_len_f32):
                pts_f32 = [
                    [float(x), float(y)]
                    for x, y in struct.iter_unpack(
                        "<ff", data[offset + 4 : offset + byte_len_f32]
                    )
                ]
                geom_score, notes = score_coordinate_sequence_2d(pts_f32)
                if geom_score >= 0.70:
                    tracker.claim(offset, byte_len_f32)
                    geom = Geometry("LineString", {"coords": pts_f32})
                    features.append(
                        GeometricFeature(
                            id=f"feat_f32_{len(layers)}_0x{offset:x}",
                            layer_id=layer_id,
                            geometry=geom,
                            bbox=geom.bounding_box(),
                            properties={
                                "vertex_count": maybe_count,
                                "encoding": "LENGTH_PREFIXED_F32_LE",
                                "stream_lineage": stream_lineage,
                            },
                            provenance=Provenance(
                                id=f"prov_f32_{len(layers)}_0x{offset:x}",
                                span=ByteSpan(offset, byte_len_f32),
                                detector="SlidingWindowFloat32Detector",
                                endianness="LITTLE_ENDIAN",
                                stream_lineage=stream_lineage,
                                host_compressed_span=host_compressed_span,
                                confidence=build_confidence(
                                    0.88,
                                    0.80,
                                    data[offset : offset + byte_len_f32],
                                    geom_score,
                                    notes,
                                ),
                            ),
                        )
                    )
                    offset += byte_len_f32
                    continue

        offset += 4

    if features:
        stroke, fill = LAYER_PALETTE[len(layers) % len(LAYER_PALETTE)]
        layer_name = (
            "heuristic_coordinate_runs"
            if stream_lineage == "root"
            else f"decompressed_vectors ({stream_lineage})"
        )
        layers.append(
            Layer(
                id=layer_id,
                name=layer_name,
                style_stroke=stroke,
                style_fill=fill,
                features=features,
            )
        )


def _detect_repeating_records(
    data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    tracker: ClaimTracker,
    attribute_tables: List[AttributeTable],
) -> None:
    candidate_strides = (16, 20, 24, 32, 48, 64)
    n = len(data)
    if n < 64:
        return
    offset = 0
    while offset + 64 <= n:
        if tracker.is_claimed(offset, 48):
            offset += 4
            continue
        matched = False
        for stride in candidate_strides:
            if offset + stride * 4 > n:
                continue
            first_id = struct.unpack("<I", data[offset : offset + 4])[0]
            if first_id == 0 or first_id > 100000:
                continue
            count = 1
            while (
                offset + (count + 1) * stride <= n
                and not tracker.is_claimed(offset + count * stride, stride)
            ):
                next_id = struct.unpack(
                    "<I",
                    data[offset + count * stride : offset + count * stride + 4],
                )[0]
                if next_id == first_id + count:
                    count += 1
                else:
                    break
            if count >= 4:
                total_bytes = count * stride
                tracker.claim(offset, total_bytes)
                chunk = data[offset : offset + total_bytes]
                rows: List[Dict[str, Any]] = []
                for r in range(count):
                    r_slice = chunk[r * stride : (r + 1) * stride]
                    rec_id, val_f32 = struct.unpack("<If", r_slice[:8])
                    ascii_part = (
                        r_slice[8 : min(stride, 24)]
                        .split(b"\x00", 1)[0]
                        .decode("utf-8", errors="replace")
                        .strip()
                    )
                    row_obj: Dict[str, Any] = {"record_id": rec_id}
                    if math.isfinite(val_f32) and abs(val_f32) < 1e8:
                        row_obj["field_f32"] = round(float(val_f32), 4)
                    row_obj["ascii_payload"] = ascii_part
                    rows.append(row_obj)

                tbl_idx = len(attribute_tables)
                attribute_tables.append(
                    AttributeTable(
                        id=f"table_heuristic_{tbl_idx}_0x{offset:x}",
                        name=f"heuristic_records_0x{offset:x}",
                        record_stride=stride,
                        record_count=count,
                        columns=[
                            ColumnSchema("record_id", "UINT32", 0, 4),
                            ColumnSchema("field_f32", "FLOAT32", 4, 4),
                            ColumnSchema("ascii_payload", "ASCII", 8, stride - 8),
                        ],
                        rows=rows,
                        provenance=Provenance(
                            id=f"prov_table_{tbl_idx}_0x{offset:x}",
                            span=ByteSpan(offset, total_bytes),
                            detector="SlidingStrideRecordDetector",
                            endianness="LITTLE_ENDIAN",
                            stream_lineage=stream_lineage,
                            host_compressed_span=host_compressed_span,
                            confidence=build_confidence(
                                0.90,
                                0.85,
                                chunk,
                                0.85,
                                [f"Sequential u32 key with fixed stride {stride} across {count} records"],
                            ),
                        ),
                    )
                )
                offset += total_bytes
                matched = True
                break
        if not matched:
            offset += 4


def _detect_opaque_regions(
    _data: bytes,
    stream_lineage: str,
    host_compressed_span: Optional[ByteSpan],
    entropy_profile: List[EntropyWindow],
    tracker: ClaimTracker,
    embedded_assets: List[EmbeddedAsset],
) -> None:
    for win in entropy_profile:
        if win.classification == "HIGH_COMPRESSED_OR_OPAQUE" and not tracker.is_claimed(
            win.offset, win.length
        ):
            tracker.claim(win.offset, win.length)
            embedded_assets.append(
                EmbeddedAsset(
                    id=f"asset_opaque_0x{win.offset:x}",
                    kind="OPAQUE_COMPRESSED_OR_ENCRYPTED",
                    description=(
                        f"Unclaimed high-entropy region ({win.shannon_entropy:.2f} bits/byte); "
                        "reported as opaque/encrypted without decryption attempt"
                    ),
                    entropy=win.shannon_entropy,
                    is_opaque=True,
                    metadata={"window_entropy": win.shannon_entropy},
                    provenance=Provenance(
                        id=f"prov_opaque_0x{win.offset:x}",
                        span=ByteSpan(win.offset, win.length),
                        detector="SlidingEntropyClassifier",
                        endianness="UNKNOWN",
                        stream_lineage=stream_lineage,
                        host_compressed_span=host_compressed_span,
                        confidence=ConfidenceBreakdown.compute(
                            0.90,
                            0.80,
                            0.95,
                            0.80,
                            ["High byte entropy not matching standard Deflate/zlib/gzip streams"],
                        ),
                    ),
                )
            )


# ==============================================================================
# 5. LOSSLESS EXPORTERS (SVG, GeoJSON, SQLite, Audit TXT/JSON, Raster TIFF/PNG)
# ==============================================================================

def export_svg(doc: DecoupledDocument, path: Path) -> None:
    bbox = doc.global_bbox or BoundingBox(0.0, 0.0, 1000.0, 1000.0)
    w_span = max(1.0, abs(bbox.max_x - bbox.min_x))
    h_span = max(1.0, abs(bbox.max_y - bbox.min_y))
    pad_x = w_span * 0.05
    pad_y = h_span * 0.05
    vb_x = bbox.min_x - pad_x
    vb_y = bbox.min_y - pad_y
    vb_w = w_span + 2.0 * pad_x
    vb_h = h_span + 2.0 * pad_y
    stroke_w = max(0.0001, max(vb_w, vb_h) * 0.0035)
    pt_r = stroke_w * 2.2

    lines: List[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f"<!-- Generated by OpenArchive Decoupler v{doc.metadata.tool_version} | Source: {doc.metadata.source_filename} (SHA-256: {doc.metadata.sha256}) -->",
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb_x} {vb_y} {vb_w} {vb_h}" width="1200" height="900">',
        f'  <rect x="{vb_x}" y="{vb_y}" width="{vb_w}" height="{vb_h}" fill="#0f172a" />',
    ]

    for layer in doc.layers:
        lines.append(
            f'  <g id="{layer.id}" data-layer-name="{layer.name}" stroke="{layer.style_stroke}" fill="{layer.style_fill}" stroke-width="{stroke_w}">'
        )
        for feat in layer.features:
            off = feat.provenance.span.offset
            length = feat.provenance.span.length
            conf = feat.provenance.confidence.composite
            lineage = feat.provenance.stream_lineage
            t = feat.geometry.type
            d = feat.geometry.data

            if t == "Point":
                c = d["coord"]
                lines.append(
                    f'    <circle id="{feat.id}" cx="{c[0]}" cy="{c[1]}" r="{pt_r}" fill="{layer.style_stroke}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}" />'
                )
            elif t == "MultiPoint":
                lines.append(
                    f'    <g id="{feat.id}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}">'
                )
                for c in d["coords"]:
                    lines.append(
                        f'      <circle cx="{c[0]}" cy="{c[1]}" r="{pt_r}" fill="{layer.style_stroke}" />'
                    )
                lines.append("    </g>")
            elif t == "LineString":
                pts_str = " ".join(f"{c[0]},{c[1]}" for c in d["coords"])
                lines.append(
                    f'    <polyline id="{feat.id}" fill="none" points="{pts_str}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}" />'
                )
            elif t == "MultiLineString":
                parts: List[str] = []
                for line in d["lines"]:
                    for i, c in enumerate(line):
                        parts.append(f"{'M' if i == 0 else 'L'} {c[0]} {c[1]}")
                path_d = " ".join(parts)
                lines.append(
                    f'    <path id="{feat.id}" fill="none" d="{path_d}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}" />'
                )
            elif t == "Polygon":
                parts = []
                for ring in d["rings"]:
                    for i, c in enumerate(ring):
                        parts.append(f"{'M' if i == 0 else 'L'} {c[0]} {c[1]}")
                    parts.append("Z")
                path_d = " ".join(parts)
                lines.append(
                    f'    <path id="{feat.id}" fill-rule="evenodd" d="{path_d}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}" />'
                )
            elif t == "CubicBezier":
                cps = d["control_points"]
                if cps:
                    cmd = [f"M {cps[0][0]} {cps[0][1]}"]
                    idx = 1
                    while idx + 2 < len(cps):
                        cmd.append(
                            f"C {cps[idx][0]} {cps[idx][1]}, {cps[idx+1][0]} {cps[idx+1][1]}, {cps[idx+2][0]} {cps[idx+2][1]}"
                        )
                        idx += 3
                    lines.append(
                        f'    <path id="{feat.id}" fill="none" d="{" ".join(cmd)}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}" />'
                    )
            elif t == "RegularGrid":
                ox, oy = d["origin"]
                sx, sy = d["spacing"]
                cols, rows_cnt = d["dims"]
                lines.append(
                    f'    <g id="{feat.id}" data-grid-dims="{cols}x{rows_cnt}" data-offset="{off}" data-length="{length}" data-stream-lineage="{lineage}" data-confidence="{conf:.4f}">'
                )
                for r in range(rows_cnt):
                    for c in range(cols):
                        x = ox + c * sx
                        y = oy + r * sy
                        lines.append(
                            f'      <circle cx="{x}" cy="{y}" r="{pt_r * 0.7}" />'
                        )
                lines.append("    </g>")

        lines.append("  </g>")
    lines.append("</svg>\n")
    path.write_text("\n".join(lines), encoding="utf-8")


def export_geojson(doc: DecoupledDocument, path: Path) -> None:
    features_json: List[Dict[str, Any]] = []
    for layer in doc.layers:
        for feat in layer.features:
            t = feat.geometry.type
            d = feat.geometry.data
            if t == "Point":
                coords = list(d["coord"])
                if d.get("z") is not None:
                    coords.append(d["z"])
                geom_val = {"type": "Point", "coordinates": coords}
            elif t == "MultiPoint":
                geom_val = {"type": "MultiPoint", "coordinates": d["coords"]}
            elif t == "LineString":
                geom_val = {"type": "LineString", "coordinates": d["coords"]}
            elif t == "MultiLineString":
                geom_val = {"type": "MultiLineString", "coordinates": d["lines"]}
            elif t == "Polygon":
                geom_val = {"type": "Polygon", "coordinates": d["rings"]}
            elif t == "MultiPolygon":
                geom_val = {"type": "MultiPolygon", "coordinates": d["polygons"]}
            elif t == "CubicBezier":
                geom_val = {
                    "type": "LineString",
                    "coordinates": d["control_points"],
                    "curve_encoding": "CubicBezierControlPolygon",
                }
            elif t == "RegularGrid":
                ox, oy = d["origin"]
                sx, sy = d["spacing"]
                cols, rows_cnt = d["dims"]
                vals = d["values"]
                pts = []
                for r in range(rows_cnt):
                    for c in range(cols):
                        idx = r * cols + c
                        z = vals[idx] if idx < len(vals) else 0.0
                        pts.append([ox + c * sx, oy + r * sy, z])
                geom_val = {"type": "MultiPoint", "coordinates": pts}
            else:
                geom_val = {"type": "MultiPoint", "coordinates": d.get("vertices", [])}

            props: Dict[str, Any] = {
                "feature_id": feat.id,
                "layer_id": layer.id,
                "layer_name": layer.name,
                "geometry_kind": t,
                "byte_offset": feat.provenance.span.offset,
                "byte_length": feat.provenance.span.length,
                "stream_lineage": feat.provenance.stream_lineage,
                "detector": feat.provenance.detector,
                "confidence": feat.provenance.confidence.composite,
            }
            if feat.provenance.host_compressed_span is not None:
                props["host_compressed_offset"] = feat.provenance.host_compressed_span.offset
                props["host_compressed_length"] = feat.provenance.host_compressed_span.length
            props.update(feat.properties)
            features_json.append(
                {
                    "type": "Feature",
                    "id": feat.id,
                    "geometry": geom_val,
                    "properties": props,
                }
            )

    collection = {
        "type": "FeatureCollection",
        "metadata": {
            "source_filename": doc.metadata.source_filename,
            "sha256": doc.metadata.sha256,
            "format_family": doc.metadata.format_family,
            "crs": dataclasses.asdict(doc.coordinate_system),
            "decompressed_streams": [dataclasses.asdict(ds) for ds in doc.decompressed_streams],
        },
        "features": features_json,
    }
    path.write_text(json.dumps(collection, indent=2), encoding="utf-8")


def export_sqlite(doc: DecoupledDocument, path: Path) -> None:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    try:
        cur = conn.cursor()
        cur.executescript(
            """
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
            """
        )

        cur.execute(
            "INSERT INTO document_metadata VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                doc.metadata.source_filename,
                doc.metadata.file_size,
                doc.metadata.sha256,
                doc.metadata.detected_magic,
                doc.metadata.format_family,
                doc.metadata.overall_entropy,
                doc.coordinate_system.crs_type,
                doc.coordinate_system.epsg_hint,
                doc.metadata.tool_version,
            ),
        )

        for ds in doc.decompressed_streams:
            cur.execute(
                "INSERT INTO decompressed_streams VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ds.stream_id,
                    ds.parent_lineage,
                    ds.depth,
                    ds.codec,
                    ds.host_offset,
                    ds.compressed_length,
                    ds.decompressed_length,
                    ds.expansion_ratio,
                    ds.sha256,
                ),
            )

        def insert_prov(p: Provenance, entity_id: str, kind: str) -> None:
            host_off = p.host_compressed_span.offset if p.host_compressed_span else None
            host_len = p.host_compressed_span.length if p.host_compressed_span else None
            cur.execute(
                "INSERT INTO provenance VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    p.id,
                    entity_id,
                    kind,
                    p.stream_lineage,
                    host_off,
                    host_len,
                    p.span.offset,
                    p.span.length,
                    p.detector,
                    p.endianness,
                    p.confidence.composite,
                    p.confidence.internal_consistency,
                    p.confidence.pointer_validity,
                    p.confidence.entropy_score,
                    p.confidence.geometric_plausibility,
                    json.dumps(p.confidence.notes),
                ),
            )

        for layer in doc.layers:
            for feat in layer.features:
                p = feat.provenance
                insert_prov(p, feat.id, "GEOMETRY")
                bb = feat.bbox
                cur.execute(
                    "INSERT INTO geometries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        feat.id,
                        layer.id,
                        layer.name,
                        feat.geometry.type,
                        feat.geometry.vertex_count(),
                        bb.min_x if bb else None,
                        bb.min_y if bb else None,
                        bb.max_x if bb else None,
                        bb.max_y if bb else None,
                        json.dumps(dataclasses.asdict(feat.geometry)),
                        json.dumps(feat.properties),
                        p.id,
                        p.stream_lineage,
                        p.span.offset,
                        p.confidence.composite,
                    ),
                )

        for tbl in doc.attribute_tables:
            p = tbl.provenance
            insert_prov(p, tbl.id, "ATTRIBUTE_TABLE")
            cur.execute(
                "INSERT INTO attribute_tables VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tbl.id,
                    tbl.name,
                    tbl.record_stride,
                    tbl.record_count,
                    json.dumps([dataclasses.asdict(c) for c in tbl.columns]),
                    p.id,
                    p.span.offset,
                    p.confidence.composite,
                ),
            )
            for r_idx, row in enumerate(tbl.rows):
                cur.execute(
                    "INSERT INTO attribute_rows VALUES (?, ?, ?)",
                    (tbl.id, r_idx, json.dumps(row)),
                )

        for tile in doc.raster_tiles:
            p = tile.provenance
            insert_prov(p, tile.id, "RASTER_TILE")
            cur.execute(
                "INSERT INTO raster_tiles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tile.id,
                    tile.width,
                    tile.height,
                    tile.channels,
                    tile.bit_depth,
                    tile.format,
                    tile.exported_path,
                    p.id,
                    p.span.offset,
                    p.confidence.composite,
                ),
            )

        for asset in doc.embedded_assets:
            p = asset.provenance
            insert_prov(p, asset.id, "EMBEDDED_ASSET")
            cur.execute(
                "INSERT INTO embedded_assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    asset.id,
                    asset.kind,
                    asset.description,
                    asset.entropy,
                    1 if asset.is_opaque else 0,
                    json.dumps(asset.metadata),
                    p.id,
                    p.span.offset,
                    p.span.length,
                    p.confidence.composite,
                ),
            )

        conn.commit()
    finally:
        conn.close()


def export_rasters(doc: DecoupledDocument, out_dir: Path) -> List[str]:
    written: List[str] = []
    for tile in doc.raster_tiles:
        if not tile.data:
            continue
        if tile.format == "EMBEDDED_PNG":
            fname = f"{tile.id}.png"
            (out_dir / fname).write_bytes(tile.data)
            tile.exported_path = fname
            written.append(fname)
        else:
            fname = f"{tile.id}.tiff"
            _write_uncompressed_tiff(
                out_dir / fname, tile.width, tile.height, tile.channels, tile.data
            )
            tile.exported_path = fname
            written.append(fname)
    return written


def _write_uncompressed_tiff(
    path: Path, width: int, height: int, channels: int, pixels: bytes
) -> None:
    num_tags = 8
    ifd_offset = 8
    ifd_size = 2 + num_tags * 12 + 4
    bps_offset = ifd_offset + ifd_size
    pixel_offset = bps_offset + 8

    photometric = 2 if channels >= 3 else 1
    byte_count = min(len(pixels), width * height * channels)

    buf = bytearray()
    buf += b"II" + struct.pack("<HI", 42, ifd_offset)
    buf += struct.pack("<H", num_tags)

    def add_tag(tag: int, ftype: int, count: int, val: int) -> None:
        buf.extend(struct.pack("<HHII", tag, ftype, count, val))

    add_tag(256, 4, 1, width)
    add_tag(257, 4, 1, height)
    if channels == 3:
        add_tag(258, 3, 3, bps_offset)
    else:
        add_tag(258, 3, 1, 8)
    add_tag(259, 3, 1, 1)
    add_tag(262, 3, 1, photometric)
    add_tag(273, 4, 1, pixel_offset)
    add_tag(277, 3, 1, channels)
    add_tag(279, 4, 1, byte_count)
    buf += struct.pack("<I", 0)
    buf += struct.pack("<HHHH", 8, 8, 8, 0)
    buf += pixels[:byte_count]
    path.write_bytes(bytes(buf))


def export_ir_json(doc: DecoupledDocument, path: Path) -> None:
    path.write_text(json.dumps(doc.to_dict(), indent=2), encoding="utf-8")


def export_audit_txt(doc: DecoupledDocument, path: Path) -> None:
    lines: List[str] = [
        "=" * 80,
        " OPENARCHIVE DECOUPLER — STRUCTURAL BINARY AUDIT REPORT",
        "=" * 80,
        f"Source File      : {doc.metadata.source_filename}",
        f"File Size        : {doc.metadata.file_size} bytes",
        f"SHA-256 Digest   : {doc.metadata.sha256}",
        f"Detected Magic   : {doc.metadata.detected_magic}",
        f"Format Family    : {doc.metadata.format_family}",
        f"Overall Entropy  : {doc.metadata.overall_entropy:.4f} bits/byte",
        f"Endianness Hint  : {doc.metadata.endianness_hint}",
        f"CRS Hint         : {doc.coordinate_system.crs_type} ({doc.coordinate_system.units})",
    ]
    if doc.coordinate_system.epsg_hint is not None:
        lines.append(f"EPSG Code Hint   : EPSG:{doc.coordinate_system.epsg_hint}")
    if doc.coordinate_system.affine_matrix is not None:
        m = doc.coordinate_system.affine_matrix
        lines.append(
            f"Affine Matrix    : [a={m[0]:.6f}, b={m[1]:.6f}, c={m[2]:.6f}, d={m[3]:.6f}, tx={m[4]:.6f}, ty={m[5]:.6f}]"
        )
    if doc.global_bbox is not None:
        b = doc.global_bbox
        lines.append(
            f"Global BBox      : min=({b.min_x}, {b.min_y}), max=({b.max_x}, {b.max_y})"
        )
    lines.append(
        f"Carved Streams   : {len(doc.decompressed_streams)} decompressed virtual sub-stream(s)"
    )
    for ds in doc.decompressed_streams:
        lines.append(
            f"  * [{ds.stream_id}] codec={ds.codec} depth={ds.depth} parent={ds.parent_lineage} "
            f"host_offset=0x{ds.host_offset:06x} ({ds.compressed_length} B -> {ds.decompressed_length} B, ratio={ds.expansion_ratio:.2f}:1)"
        )
    lines.append("")

    lines.extend(
        [
            "-" * 80,
            f" 1. RECOVERED VECTOR LAYERS & GEOMETRIC STRUCTURES ({len(doc.layers)} layers, {doc.total_features()} features)",
            "-" * 80,
        ]
    )
    for layer in doc.layers:
        lines.append(
            f'\n[Layer {layer.id}] name="{layer.name}" features={len(layer.features)} stroke={layer.style_stroke}'
        )
        for feat in layer.features:
            p = feat.provenance
            lines.append(
                f"  - Feature {feat.id:<18} | Kind: {feat.geometry.type:<14} | Vertices: {feat.geometry.vertex_count():<5} "
                f"| Bytes: 0x{p.span.offset:06x}..0x{p.span.end:06x} ({p.span.length} B) | Confidence: {p.confidence.composite:.4f}"
            )
            lines.append(
                f"    Detector: {p.detector} | Lineage: {p.stream_lineage} | Breakdown: [consistency={p.confidence.internal_consistency:.2f}, "
                f"ptr={p.confidence.pointer_validity:.2f}, entropy={p.confidence.entropy_score:.2f}, geom={p.confidence.geometric_plausibility:.2f}]"
            )
            for note in p.confidence.notes:
                lines.append(f"    * {note}")
    lines.append("")

    lines.extend(
        [
            "-" * 80,
            f" 2. RECOVERED ATTRIBUTE TABLES ({len(doc.attribute_tables)} tables)",
            "-" * 80,
        ]
    )
    for tbl in doc.attribute_tables:
        p = tbl.provenance
        lines.append(
            f'\n[Table {tbl.id}] name="{tbl.name}" stride={tbl.record_stride}B rows={tbl.record_count} '
            f"| Lineage: {p.stream_lineage} | Bytes: 0x{p.span.offset:06x}..0x{p.span.end:06x} ({p.span.length} B) | Confidence: {p.confidence.composite:.4f}"
        )
        for idx, row in enumerate(tbl.rows[:10]):
            lines.append(f"  Row {idx:<3}: {json.dumps(row)}")
    lines.append("")

    lines.extend(
        [
            "-" * 80,
            f" 3. RECOVERED RASTER TILES ({len(doc.raster_tiles)} tiles)",
            "-" * 80,
        ]
    )
    for tile in doc.raster_tiles:
        p = tile.provenance
        lines.append(
            f"  - Raster {tile.id:<16} | {tile.width}x{tile.height}x{tile.channels} ({tile.format}) "
            f"| Lineage: {p.stream_lineage} | Bytes: 0x{p.span.offset:06x}..0x{p.span.end:06x} ({p.span.length} B) | Confidence: {p.confidence.composite:.4f} | Exported: {tile.exported_path}"
        )
    lines.append("")

    lines.extend(
        [
            "-" * 80,
            f" 4. EMBEDDED ASSETS, POINTER TABLES & OPAQUE REGIONS ({len(doc.embedded_assets)} blocks)",
            "-" * 80,
        ]
    )
    for asset in doc.embedded_assets:
        p = tile_p = asset.provenance
        lines.append(
            f"  - Asset {asset.id:<18} | Kind: {asset.kind:<30} | Opaque: {str(asset.is_opaque):<5} | Entropy: {asset.entropy:.3f} "
            f"| Lineage: {tile_p.stream_lineage} | Bytes: 0x{p.span.offset:06x}..0x{p.span.end:06x} ({p.span.length} B) | Confidence: {p.confidence.composite:.4f}"
        )
        lines.append(f"    Description: {asset.description}")
    lines.append("")

    lines.extend(
        [
            "-" * 80,
            f" 5. ENTROPY PROFILE ({len(doc.entropy_profile)} windows)",
            "-" * 80,
        ]
    )
    for win in doc.entropy_profile:
        lines.append(
            f"  Bytes 0x{win.offset:06x}..0x{win.offset + win.length:06x} ({win.length:>4} B) | Entropy: {win.shannon_entropy:.4f} bits/byte | {win.classification}"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ==============================================================================
# 6. CLI & BATCH RUNNER + OPTIONAL TKINTER GUI
# ==============================================================================

def process_single_file(
    input_path: Path,
    out_dir: Path,
    formats: List[str],
    min_confidence: float,
    dry_run: bool,
    verbose: bool,
    carver_cfg: Optional[CarverConfig] = None,
) -> DecoupledDocument:
    with input_path.open("rb") as f:
        size = input_path.stat().st_size
        if size > 0:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                raw_bytes = bytes(mm)
        else:
            raw_bytes = b""

    if verbose:
        print(f"[scan] Memory-mapped '{input_path.name}' ({len(raw_bytes)} bytes, read-only)")

    doc = scan_binary(
        input_path.name,
        raw_bytes,
        min_confidence=min_confidence,
        carver_cfg=carver_cfg,
        verbose=verbose,
    )

    print(
        f'[decouple] {doc.metadata.source_filename} | size={doc.metadata.file_size} B '
        f'| magic="{doc.metadata.detected_magic}" | entropy={doc.metadata.overall_entropy:.3f} '
        f"| carved_streams={len(doc.decompressed_streams)} "
        f"| layers={len(doc.layers)} | features={doc.total_features()} "
        f"| tables={len(doc.attribute_tables)} | rasters={len(doc.raster_tiles)} "
        f"| assets={len(doc.embedded_assets)}"
    )

    if dry_run:
        return doc

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = input_path.stem

    if any(fmt in formats for fmt in ("tiff", "png", "raster")):
        written = export_rasters(doc, out_dir)
        if verbose and written:
            print(f"[export] Wrote {len(written)} raster tile(s): {written}")

    if "svg" in formats:
        p = out_dir / f"{stem}.svg"
        export_svg(doc, p)
        if verbose:
            print(f"[export] SVG -> {p}")

    if "geojson" in formats:
        p = out_dir / f"{stem}.geojson"
        export_geojson(doc, p)
        if verbose:
            print(f"[export] GeoJSON -> {p}")

    if "sqlite" in formats or "db" in formats:
        p = out_dir / f"{stem}.sqlite"
        export_sqlite(doc, p)
        if verbose:
            print(f"[export] SQLite -> {p}")

    if "txt" in formats:
        p = out_dir / f"{stem}_audit.txt"
        export_audit_txt(doc, p)
        if verbose:
            print(f"[export] Audit TXT -> {p}")

    if "json" in formats:
        p = out_dir / f"{stem}_ir.json"
        export_ir_json(doc, p)
        if verbose:
            print(f"[export] IR JSON -> {p}")

    return doc


def launch_tkinter_gui(initial_doc: Optional[DecoupledDocument], out_dir: Path) -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("OpenArchive Decoupler — Local Binary Workbench")
    root.geometry("1120x720")
    root.configure(bg="#0f172a")

    state = {"doc": initial_doc}

    top_bar = tk.Frame(root, bg="#1e293b", padx=10, pady=8)
    top_bar.pack(fill=tk.X)

    lbl_status = tk.Label(
        top_bar,
        text="Ready (Offline / Read-Only Mode)",
        bg="#1e293b",
        fg="#38bdf8",
        font=("Consolas", 11, "bold"),
    )
    lbl_status.pack(side=tk.LEFT)

    canvas = tk.Canvas(root, bg="#020617", highlightthickness=0)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)

    right_panel = tk.Frame(root, bg="#1e293b", width=420, padx=8, pady=8)
    right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=8, pady=8)

    tree = ttk.Treeview(
        right_panel,
        columns=("kind", "lineage", "conf"),
        show="headings",
        height=24,
    )
    tree.heading("kind", text="Structure")
    tree.heading("lineage", text="Lineage / Offset")
    tree.heading("conf", text="Confidence")
    tree.column("kind", width=140)
    tree.column("lineage", width=180)
    tree.column("conf", width=80)
    tree.pack(fill=tk.BOTH, expand=True)

    def render_doc(doc: Optional[DecoupledDocument]) -> None:
        canvas.delete("all")
        for item in tree.get_children():
            tree.delete(item)
        if not doc:
            return
        lbl_status.config(
            text=f"{doc.metadata.source_filename} ({doc.metadata.file_size} B) | Carved Streams: {len(doc.decompressed_streams)}"
        )
        for layer in doc.layers:
            for feat in layer.features:
                tree.insert(
                    "",
                    tk.END,
                    values=(
                        f"{feat.id} ({feat.geometry.type})",
                        f"{feat.provenance.stream_lineage} @ 0x{feat.provenance.span.offset:x}",
                        f"{feat.provenance.confidence.composite:.3f}",
                    ),
                )

        bb = doc.global_bbox
        if not bb:
            return
        w = max(1.0, bb.max_x - bb.min_x)
        h = max(1.0, bb.max_y - bb.min_y)
        cw = 660
        ch = 620
        for layer in doc.layers:
            for feat in layer.features:
                coords = feat.geometry.data.get("coords") or (
                    feat.geometry.data.get("rings", [[]])[0]
                )
                if coords and len(coords) >= 2:
                    flat_pts = []
                    for x, y in coords:
                        px = 30 + ((x - bb.min_x) / w) * (cw - 60)
                        py = ch - (30 + ((y - bb.min_y) / h) * (ch - 60))
                        flat_pts.extend([px, py])
                    canvas.create_line(*flat_pts, fill=layer.style_stroke, width=2)

    def open_binary() -> None:
        p = filedialog.askopenfilename(title="Select Binary File to Decouple")
        if p:
            doc = process_single_file(
                Path(p),
                out_dir,
                ["svg", "geojson", "sqlite", "txt", "json", "tiff"],
                0.60,
                False,
                True,
            )
            state["doc"] = doc
            render_doc(doc)
            messagebox.showinfo(
                "Decouple Complete",
                f"Recovered {doc.total_features()} features ({len(doc.decompressed_streams)} carved streams) and exported to {out_dir}",
            )

    btn_open = tk.Button(
        top_bar,
        text="Open & Decouple Binary...",
        command=open_binary,
        bg="#0284c7",
        fg="white",
    )
    btn_open.pack(side=tk.RIGHT)

    render_doc(initial_doc)
    root.mainloop()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="decouple",
        description="OpenArchive Decoupler — Offline structural binary reverse-engineering and universal format extractor.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input binary file or directory (for batch mode).",
    )
    parser.add_argument(
        "--out",
        "-o",
        default="decoupled_out",
        help="Output directory for unpacked universal artifacts (default: decoupled_out).",
    )
    parser.add_argument(
        "--format",
        "-f",
        default="svg,geojson,sqlite,txt,json,tiff",
        help="Comma-separated list of exporters: svg,geojson,sqlite,txt,json,tiff",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.60,
        help="Minimum composite confidence threshold in [0.0, 1.0] (default: 0.60).",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Enable forensic aggressive mode (lowers raw Deflate entropy threshold to 6.8, increases recursion depth to 5, and probes all valid CMF/FLG zlib headers).",
    )
    parser.add_argument(
        "--deflate-entropy",
        type=float,
        default=7.20,
        help="Minimum Shannon entropy [0.0 .. 8.0] required to trigger length-prefixed raw Deflate carving (default: 7.20).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum recursion depth for nested compressed stream carving (default: 3).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and report discovered structures without writing output files.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed structural discovery, stream carving, and export diagnostics.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the local offline Tkinter inspection workbench.",
    )

    args = parser.parse_args(argv)
    if not args.input and not args.gui:
        parser.print_help()
        return 1

    formats = [s.strip().lower() for s in args.format.split(",") if s.strip()]
    out_dir = Path(args.out)
    carver_cfg = CarverConfig(
        deflate_entropy_threshold=args.deflate_entropy,
        min_high_entropy_run=64,
        max_recursion_depth=args.max_depth,
        scan_step=32,
        aggressive=args.aggressive,
        verbose=args.verbose,
    )
    if args.aggressive:
        carver_cfg.apply_aggressive()

    last_doc: Optional[DecoupledDocument] = None

    if args.input:
        in_path = Path(args.input)
        if not in_path.exists():
            print(f"Error: input path '{in_path}' does not exist.", file=sys.stderr)
            return 2

        if in_path.is_dir():
            files = sorted(p for p in in_path.iterdir() if p.is_file())
            manifest: List[Dict[str, Any]] = []
            for fpath in files:
                sub_out = out_dir / fpath.stem
                doc = process_single_file(
                    fpath,
                    sub_out,
                    formats,
                    args.min_confidence,
                    args.dry_run,
                    args.verbose,
                    carver_cfg=carver_cfg,
                )
                opaque_cnt = sum(1 for a in doc.embedded_assets if a.is_opaque)
                manifest.append(
                    {
                        "source_file": doc.metadata.source_filename,
                        "sha256": doc.metadata.sha256,
                        "file_size": doc.metadata.file_size,
                        "detected_magic": doc.metadata.detected_magic,
                        "decompressed_streams_carved": len(doc.decompressed_streams),
                        "layers_recovered": len(doc.layers),
                        "features_recovered": doc.total_features(),
                        "attribute_tables_recovered": len(doc.attribute_tables),
                        "raster_tiles_recovered": len(doc.raster_tiles),
                        "opaque_regions_flagged": opaque_cnt,
                        "output_directory": str(sub_out),
                    }
                )
                last_doc = doc

            if not args.dry_run:
                out_dir.mkdir(parents=True, exist_ok=True)
                manifest_path = out_dir / "batch_manifest.json"
                manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                if args.verbose:
                    print(f"[batch] Wrote deterministic manifest -> {manifest_path}")
        else:
            last_doc = process_single_file(
                in_path,
                out_dir,
                formats,
                args.min_confidence,
                args.dry_run,
                args.verbose,
                carver_cfg=carver_cfg,
            )

    if args.gui:
        launch_tkinter_gui(last_doc, out_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
