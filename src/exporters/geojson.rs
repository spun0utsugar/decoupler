use crate::ir::{AttributeValue, DecoupledDocument, Geometry};
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

/// Exports all recovered vector layers into an RFC 7946 GeoJSON `FeatureCollection`,
/// preserving full numerical precision, original byte spans, and confidence breakdowns.
pub fn export_geojson(doc: &DecoupledDocument, path: &Path) -> std::io::Result<()> {
    let mut features_json = Vec::new();

    for layer in &doc.layers {
        for feat in &layer.features {
            let geom_val = match &feat.geometry {
                Geometry::Point { coord, z } => {
                    if let Some(zv) = z {
                        json!({ "type": "Point", "coordinates": [coord[0], coord[1], zv] })
                    } else {
                        json!({ "type": "Point", "coordinates": [coord[0], coord[1]] })
                    }
                }
                Geometry::MultiPoint { coords } => {
                    json!({ "type": "MultiPoint", "coordinates": coords })
                }
                Geometry::LineString { coords } => {
                    json!({ "type": "LineString", "coordinates": coords })
                }
                Geometry::MultiLineString { lines } => {
                    json!({ "type": "MultiLineString", "coordinates": lines })
                }
                Geometry::Polygon { rings } => {
                    json!({ "type": "Polygon", "coordinates": rings })
                }
                Geometry::MultiPolygon { polygons } => {
                    json!({ "type": "MultiPolygon", "coordinates": polygons })
                }
                Geometry::CubicBezier { control_points } => {
                    json!({
                        "type": "LineString",
                        "coordinates": control_points,
                        "curve_encoding": "CubicBezierControlPolygon"
                    })
                }
                Geometry::RegularGrid {
                    origin,
                    spacing,
                    dims,
                    values,
                } => {
                    let mut pts = Vec::with_capacity(dims[0] * dims[1]);
                    for r in 0..dims[1] {
                        for c in 0..dims[0] {
                            let idx = r * dims[0] + c;
                            let z = values.get(idx).copied().unwrap_or(0.0);
                            pts.push(vec![
                                origin[0] + (c as f64) * spacing[0],
                                origin[1] + (r as f64) * spacing[1],
                                z,
                            ]);
                        }
                    }
                    json!({ "type": "MultiPoint", "coordinates": pts })
                }
                Geometry::SimpleMesh { vertices, .. } => {
                    json!({ "type": "MultiPoint", "coordinates": vertices })
                }
            };

            let mut props = Map::new();
            props.insert("feature_id".to_string(), json!(feat.id));
            props.insert("layer_id".to_string(), json!(layer.id));
            props.insert("layer_name".to_string(), json!(layer.name));
            props.insert("geometry_kind".to_string(), json!(feat.geometry.kind_name()));
            props.insert("byte_offset".to_string(), json!(feat.provenance.span.offset));
            props.insert("byte_length".to_string(), json!(feat.provenance.span.length));
            props.insert(
                "stream_lineage".to_string(),
                json!(feat.provenance.stream_lineage),
            );
            if let Some(host_span) = feat.provenance.host_compressed_span {
                props.insert("host_compressed_offset".to_string(), json!(host_span.offset));
                props.insert("host_compressed_length".to_string(), json!(host_span.length));
            }
            props.insert("detector".to_string(), json!(feat.provenance.detector));
            props.insert(
                "confidence".to_string(),
                json!(feat.provenance.confidence.composite),
            );

            for (k, v) in &feat.properties {
                let jv = match v {
                    AttributeValue::Int(i) => json!(i),
                    AttributeValue::Float(f) => json!(f),
                    AttributeValue::Text(s) => json!(s),
                    AttributeValue::Bool(b) => json!(b),
                    AttributeValue::BytesHex(h) => json!(h),
                    AttributeValue::Null => Value::Null,
                };
                props.insert(k.clone(), jv);
            }

            features_json.push(json!({
                "type": "Feature",
                "id": feat.id,
                "geometry": geom_val,
                "properties": props
            }));
        }
    }

    let collection = json!({
        "type": "FeatureCollection",
        "metadata": {
            "source_filename": doc.metadata.source_filename,
            "sha256": doc.metadata.sha256,
            "format_family": doc.metadata.format_family,
            "crs": doc.coordinate_system,
            "decompressed_streams": doc.decompressed_streams
        },
        "features": features_json
    });

    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &collection)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}
