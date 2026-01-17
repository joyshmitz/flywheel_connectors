//! Serde module for serializing `Vec<u8>` as Hex (human-readable) or Bytes (binary).

use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a byte vec.
///
/// # Errors
/// Returns any serializer error when serialization fails.
pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        hex::serde::serialize(bytes, serializer)
    } else {
        serializer.serialize_bytes(bytes)
    }
}

/// Deserialize a byte vec.
///
/// # Errors
/// Returns an error if hex decoding fails or the underlying deserializer reports an error.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    } else {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.to_vec())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(byte) = seq.next_element()? {
                    vec.push(byte);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}
