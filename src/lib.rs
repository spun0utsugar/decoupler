pub mod carver;
pub mod exporters;
pub mod gui;
pub mod ir;
pub mod scanner;
pub mod scoring;

#[cfg(test)]
mod tests {
    use super::ir::Geometry;
    use super::scanner::{scan_binary, ScanConfig};
    use byteorder::{LittleEndian, WriteBytesExt};

    #[test]
    fn test_coordinate_sequence_and_opaque_detection() {
        let mut buf = Vec::new();
        // Write 16-byte header
        buf.extend_from_slice(b"UNKN\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        // Write length-prefixed f64 closed square polygon (5 vertices)
        buf.write_u32::<LittleEndian>(5).unwrap();
        let coords = [
            [100.0, 100.0],
            [200.0, 100.0],
            [200.0, 200.0],
            [100.0, 200.0],
            [100.0, 100.0],
        ];
        for [x, y] in coords {
            buf.write_f64::<LittleEndian>(x).unwrap();
            buf.write_f64::<LittleEndian>(y).unwrap();
        }
        // Pad to 64 bytes
        buf.resize(256, 0);

        let cfg = ScanConfig {
            min_confidence: 0.60,
            entropy_window_size: 256,
            carver: super::carver::CarverConfig::default(),
            verbose: false,
        };
        let doc = scan_binary("synthetic_square.bin", &buf, &cfg);
        assert_eq!(doc.total_features(), 1);
        let feat = &doc.layers[0].features[0];
        assert_eq!(feat.provenance.span.offset, 16);
        assert_eq!(feat.provenance.span.length, 4 + 5 * 16);
        match &feat.geometry {
            Geometry::Polygon { rings } => assert_eq!(rings[0].len(), 5),
            _ => panic!("Expected closed polygon geometry"),
        }
    }
}
