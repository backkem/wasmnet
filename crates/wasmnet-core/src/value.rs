//! A WIT value in a form every backend shares: what a portable extension reads and answers
//! ([`crate::ext::ImportServer`]), and what the browser backend's boundary carries.
//!
//! The shapes stay close to jco's own, so a page converts generically and knows nothing of an
//! interface: an option's value is sent bare, `list<u8>` is bytes, a tuple is a list, a record's
//! fields go by their WIT (kebab-case) names, a variant or a `result` is a tag and a payload, an
//! enum is its case's name, and a resource is its name and the handle its server chose.

/// One WIT value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `option::none` (JavaScript: `undefined`).
    None,
    /// `option::some` (JavaScript: the value itself). JavaScript sends a present option as
    /// the bare value.
    Some(Box<Value>),
    Bool(bool),
    /// Unsigned integers up to 32 bits (JavaScript: a number).
    U32(u32),
    /// 64-bit unsigned integers (JavaScript: a bigint).
    U64(u64),
    Str(String),
    /// `list<u8>` (JavaScript: a `Uint8Array`).
    Bytes(Vec<u8>),
    List(Vec<Value>),
    /// JavaScript: an array, like a list.
    Tuple(Vec<Value>),
    /// Fields by their WIT (kebab-case) names; JavaScript camel-cases them.
    Record(Vec<(String, Value)>),
    /// A variant case or a `result` (`ok`/`err`); JavaScript: `{ tag, val }`.
    Variant(String, Option<Box<Value>>),
    /// JavaScript: the case's name.
    Enum(String),
    /// A resource (`own` or `borrow`): its WIT name (`bucket`) and the handle the server of
    /// its interface chose. JavaScript: an instance of the class the page made for it.
    Resource(String, u32),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Self {
        Value::Str(s.into())
    }

    /// `option<T>`.
    pub fn option(v: Option<Value>) -> Self {
        v.map_or(Value::None, |v| Value::Some(Box::new(v)))
    }

    /// A variant case with a payload.
    pub fn case(tag: &str, payload: Value) -> Self {
        Value::Variant(tag.to_owned(), Some(Box::new(payload)))
    }

    /// A record from `(field, value)` pairs.
    pub fn record(fields: Vec<(&str, Value)>) -> Self {
        Value::Record(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    /// A resource handle.
    pub fn resource(name: impl Into<String>, handle: u32) -> Self {
        Value::Resource(name.into(), handle)
    }

    /// The value of an `option` (`None` for `none`; a value sent bare counts as present).
    pub fn into_option(self) -> Option<Value> {
        match self {
            Value::None => None,
            Value::Some(v) => Some(*v),
            v => Some(v),
        }
    }
}
