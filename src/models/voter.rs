use crate::proto::Voter;
use couch_rs::{document::TypedCouchDocument, CouchDocument};
use ed25519_dalek::{PublicKey, SignatureError};
use serde_with::{
    base64::{Base64, Standard},
    formats::Padded,
    DeserializeAs, SerializeAs,
};

/// Internal voter representation.
///
/// name: Voter name.
/// group: Voter group.
/// public_key: Ed25519 public key for authentication.
/// challenge: temporary challenge store for verifying response.
/// token: Sha512 of the auth token in base64.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, CouchDocument)]
pub struct InternalVoter {
    #[serde(skip_serializing_if = "String::is_empty")]
    _id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    _rev: String,
    name: String,
    group: String,
    #[serde_as(as = "PublicKeyBase64")]
    public_key: PublicKey,
}

impl TryFrom<Voter> for InternalVoter {
    type Error = SignatureError;
    fn try_from(value: Voter) -> Result<Self, Self::Error> {
        let public_key = PublicKey::from_bytes(&value.public_key)?;
        Ok(Self {
            _id: String::default(),
            _rev: String::default(),
            name: value.name,
            group: value.group,
            public_key,
        })
    }
}

impl InternalVoter {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

struct PublicKeyBase64;

impl<'de> DeserializeAs<'de, PublicKey> for PublicKeyBase64 {
    fn deserialize_as<D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Base64::<Standard, Padded>::deserialize_as(deserializer)?;
        PublicKey::from_bytes(&bytes)
            .map_err(|_| serde::de::Error::custom("valid ed25519 public key"))
    }
}

impl SerializeAs<PublicKey> for PublicKeyBase64 {
    fn serialize_as<S>(public_key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Base64::<Standard, Padded>::serialize_as(public_key.as_bytes(), serializer)
    }
}
