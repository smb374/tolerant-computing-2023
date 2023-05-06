use couch_rs::{document::TypedCouchDocument, CouchDocument};

#[derive(Clone, Debug, Serialize, Deserialize, CouchDocument)]
pub struct DeleteDocument {
    _id: String,
    _rev: String,
    _deleted: bool,
}

impl DeleteDocument {
    pub fn from_doc<T>(doc: &T) -> Self
    where
        T: TypedCouchDocument,
    {
        Self {
            _id: doc.get_id().into_owned(),
            _rev: doc.get_rev().into_owned(),
            _deleted: true,
        }
    }
}
