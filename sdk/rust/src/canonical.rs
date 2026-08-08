use serde_json::Value;

/// Sort key implementing RFC 8785 Section 3.2.3: object property names are
/// compared as arrays of UTF-16 code units treated as unsigned integers.
///
/// Rust's `String: Ord` compares UTF-8 bytes, which is code point order. The
/// two differ for exactly one input class: a supplementary-plane character
/// (U+10000 and above) encodes in UTF-16 as a surrogate pair starting in
/// U+D800..U+DBFF, so it sorts BEFORE any character in U+E000..U+FFFF, whereas
/// code point order puts it after.
fn utf16_sort_key(key: &str) -> Vec<u16> {
    key.encode_utf16().collect()
}

/// Canonicalize `value` to HELM canonical JSON.
///
/// Conformance note (see protocols/specs/rfc/canonical-json-v1.md): keys are
/// ordered per RFC 8785 Section 3.2.3 and strings use the RFC 8785 Section
/// 3.2.2.2 escape set. Numbers are rendered by `serde_json`, which re-renders
/// the parsed value rather than preserving the source literal — the Go
/// canonicalizer preserves the literal. The two agree byte for byte only over
/// the interoperable subset (integers in ±(2^53-1)), which is the subset every
/// HELM signed artifact and published vector is confined to.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).expect("string serialization cannot fail"),
        Value::Array(values) => {
            let parts: Vec<String> = values.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|key| utf16_sort_key(key));
            let parts: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(key).expect("key serialization cannot fail");
                    format!("{}:{}", encoded_key, canonical_json(&map[key]))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_json;
    use serde::Deserialize;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    struct VectorIndex {
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        id: String,
        input: String,
        canonical: String,
    }

    #[test]
    fn test_extauthz_golden_vectors_are_canonical() {
        let root = PathBuf::from("../../reference_packs/extauthz");
        let index: VectorIndex =
            serde_json::from_str(&fs::read_to_string(root.join("vectors.json")).unwrap()).unwrap();
        for vector in index.vectors {
            let input_text = fs::read_to_string(root.join(&vector.input)).unwrap();
            let expected_raw = fs::read_to_string(root.join(&vector.canonical)).unwrap();
            let expected = expected_raw.strip_suffix('\n').unwrap_or(&expected_raw);
            let value: Value = serde_json::from_str(&input_text).unwrap();
            let actual = canonical_json(&value);
            assert_eq!(actual, expected, "{}", vector.id);
        }
    }

    #[test]
    fn canonical_json_sorts_keys_and_preserves_array_order() {
        let value: Value = serde_json::from_str(r#"{"z":3,"a":[2,1],"m":{"b":2,"a":1}}"#)
            .unwrap();
        assert_eq!(canonical_json(&value), r#"{"a":[2,1],"m":{"a":1,"b":2},"z":3}"#);
    }

    /// RFC 8785 Section 3.2.3 published sorting vector. The emoji key U+1F600
    /// is a supplementary-plane character whose UTF-16 surrogate pair
    /// (D83D DE00) sorts before the BMP key U+FB33. Code point order would put
    /// it after — this test fails on any implementation that sorts by UTF-8
    /// bytes, which this one did before 2026-08-06.
    #[test]
    fn canonical_json_sorts_object_keys_by_utf16_code_unit() {
        let value: Value = serde_json::from_str(
            r#"{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","":"Control","ö":"Latin Small Letter O With Diaeresis"}"#,
        )
        .unwrap();
        let canonical = canonical_json(&value);
        let order: Vec<&str> = ["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis", "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]
            .into_iter()
            .collect();
        let mut previous = 0usize;
        for value in order {
            let needle = format!(":\"{}\"", value);
            let index = canonical
                .find(&needle)
                .unwrap_or_else(|| panic!("{} missing from {}", value, canonical));
            assert!(index >= previous, "{} is out of RFC 8785 order in {}", value, canonical);
            previous = index;
        }
    }
}
