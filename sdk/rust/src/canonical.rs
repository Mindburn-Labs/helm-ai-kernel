use serde_json::Value;

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => {
            serde_json::to_string(text).expect("string serialization cannot fail")
        }
        Value::Array(values) => {
            let parts: Vec<String> = values.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
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
        let value: Value = serde_json::from_str(r#"{"z":3,"a":[2,1],"m":{"b":2,"a":1}}"#).unwrap();
        assert_eq!(
            canonical_json(&value),
            r#"{"a":[2,1],"m":{"a":1,"b":2},"z":3}"#
        );
    }
}
