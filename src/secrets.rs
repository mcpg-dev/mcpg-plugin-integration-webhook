//! `signing_secrets`: a list of `whsec_` secrets.
//!
//! A value here is the resolved secret, and a refused config's error is
//! printed at boot. serde's own type errors quote an unexpected string, so
//! these errors name a position and a rule only, and both visitors read
//! through `deserialize_any`: with `deserialize_seq` the format would build
//! the type error itself.

use std::fmt;

use mcpg_standard_webhooks::WhsecSecret;
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<WhsecSecret>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(SecretList)
}

/// A secret as read from its file or variable, which often ends in a
/// newline.
fn parse(value: &str) -> Result<WhsecSecret, mcpg_standard_webhooks::SecretError> {
    WhsecSecret::parse(value.trim_ascii())
}

struct SecretList;

const NOT_A_LIST: &str = "signing_secrets must be a list of whsec_ secrets";

impl<'de> Visitor<'de> for SecretList {
    type Value = Vec<WhsecSecret>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of whsec_ secrets")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut secrets = Vec::new();
        while let Some(secret) = seq.next_element_seed(SecretAt(secrets.len()))? {
            secrets.push(secret);
        }
        Ok(secrets)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Err(E::custom(NOT_A_LIST))
    }

    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Err(E::custom(NOT_A_LIST))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(de::Error::custom(NOT_A_LIST))
    }
}

/// The secret at one position of the list.
struct SecretAt(usize);

impl<'de> DeserializeSeed<'de> for SecretAt {
    type Value = WhsecSecret;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for SecretAt {
    type Value = WhsecSecret;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing_secrets[{}] as a whsec_ string", self.0)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        parse(value).map_err(|e| E::custom(format_args!("signing_secrets[{}]: {e}", self.0)))
    }

    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Err(self.not_a_string())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.not_a_string())
    }

    fn visit_map<A: de::MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.not_a_string())
    }
}

impl SecretAt {
    fn not_a_string<E: de::Error>(&self) -> E {
        E::custom(format_args!("signing_secrets[{}] must be a string", self.0))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const KEY_TEXT: &str = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(deserialize_with = "deserialize")]
        signing_secrets: Vec<WhsecSecret>,
    }

    fn parse_err(json: &str) -> String {
        serde_json::from_str::<Holder>(json)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn reads_a_list_and_trims_a_trailing_newline() {
        let holder: Holder = serde_json::from_str(&format!(
            r#"{{"signing_secrets": ["{SECRET}\n", " {SECRET}\r\n"]}}"#
        ))
        .unwrap();
        assert_eq!(holder.signing_secrets.len(), 2);
        let want = WhsecSecret::parse(SECRET).unwrap();
        assert!(holder.signing_secrets.iter().all(|s| s.same_key(&want)));
        let empty: Holder = serde_json::from_str(r#"{"signing_secrets": []}"#).unwrap();
        assert!(empty.signing_secrets.is_empty());
    }

    #[test]
    fn errors_never_quote_the_value() {
        for (json, expect) in [
            (
                format!(r#"{{"signing_secrets": "{SECRET}"}}"#),
                "must be a list",
            ),
            (
                format!(r#"{{"signing_secrets": ["{SECRET}", 7]}}"#),
                "signing_secrets[1]",
            ),
            (
                format!(r#"{{"signing_secrets": [["{SECRET}"]]}}"#),
                "signing_secrets[0] must be a string",
            ),
            (
                format!(r#"{{"signing_secrets": [{{"k": "{SECRET}"}}]}}"#),
                "signing_secrets[0] must be a string",
            ),
            (
                format!(r#"{{"signing_secrets": ["{KEY_TEXT}"]}}"#),
                "does not start with whsec_",
            ),
            (
                r#"{"signing_secrets": ["whsec_MfKQ9r8G%%%"]}"#.to_owned(),
                "not standard base64",
            ),
            (
                r#"{"signing_secrets": ["whsec_MfKQ9r8GKYqr"]}"#.to_owned(),
                "24 to 64 bytes",
            ),
        ] {
            let err = parse_err(&json);
            assert!(err.contains(expect), "{err}");
            assert!(!err.contains("MfKQ9r8G"), "{err}");
        }
    }
}
