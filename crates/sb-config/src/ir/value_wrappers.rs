use serde::{Deserialize, Serialize};

/// Listable value wrapper (Go parity: `badoption.Listable[T]`).
///
/// Accepts either `T` or `[T]` in JSON/YAML; deserializes to `Vec<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listable<T> {
    pub items: Vec<T>,
}

impl<T> Listable<T> {
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }
}

impl<'de, T> Deserialize<'de> for Listable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr<T> {
            One(T),
            Many(Vec<T>),
        }

        let items = match Repr::deserialize(deserializer)? {
            Repr::One(v) => vec![v],
            Repr::Many(v) => v,
        };
        Ok(Self { items })
    }
}

impl<T> Serialize for Listable<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.items.serialize(serializer)
    }
}

/// String-or-object wrapper (Go parity: many options accept `"x"` as shorthand for `{...}`).
///
/// Accepts either a string or an object; converts string via `T: From<String>`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StringOrObj<T>(pub T);

impl<T> From<T> for StringOrObj<T> {
    fn from(v: T) -> Self {
        Self(v)
    }
}

impl<T> StringOrObj<T> {
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<'de, T> Deserialize<'de> for StringOrObj<T>
where
    T: Deserialize<'de> + From<String>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr<T> {
            Str(String),
            Obj(T),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Str(s) => Ok(Self(T::from(s))),
            Repr::Obj(v) => Ok(Self(v)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Listable, StringOrObj};
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct WrapperObj {
        value: String,
    }

    impl From<String> for WrapperObj {
        fn from(value: String) -> Self {
            Self { value }
        }
    }

    #[test]
    fn listable_deserializes_single_or_many() {
        let one: Listable<String> = serde_json::from_value(json!("alpha")).unwrap();
        assert_eq!(one.items, vec!["alpha".to_string()]);

        let many: Listable<String> = serde_json::from_value(json!(["alpha", "beta"])).unwrap();
        assert_eq!(many.items, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn listable_serializes_as_plain_array() {
        let wrapped = Listable {
            items: vec!["alpha".to_string(), "beta".to_string()],
        };
        assert_eq!(
            serde_json::to_value(&wrapped).unwrap(),
            json!(["alpha", "beta"])
        );
    }

    #[test]
    fn string_or_obj_deserializes_string_shorthand_and_object() {
        let from_string: StringOrObj<WrapperObj> = serde_json::from_value(json!("alpha")).unwrap();
        assert_eq!(
            from_string.into_inner(),
            WrapperObj::from("alpha".to_string())
        );

        let from_object: StringOrObj<WrapperObj> =
            serde_json::from_value(json!({ "value": "beta" })).unwrap();
        assert_eq!(
            from_object.into_inner(),
            WrapperObj {
                value: "beta".to_string()
            }
        );
    }

    #[test]
    fn wp30aq_pin_value_wrapper_owner_is_value_wrappers_rs() {
        let source = include_str!("value_wrappers.rs");
        for needle in [
            "pub struct Listable<T>",
            "pub struct StringOrObj<T>(pub T);",
        ] {
            assert!(
                source.contains(needle),
                "expected `{needle}` to live in ir/value_wrappers.rs"
            );
        }
    }

    #[test]
    fn wp30aq_pin_mod_rs_only_reexports_value_wrappers() {
        let source = include_str!("mod.rs");
        assert!(
            source.contains("mod value_wrappers;")
                && source.contains("pub use value_wrappers::{Listable, StringOrObj};"),
            "expected ir/mod.rs to re-export Listable/StringOrObj from ir/value_wrappers.rs"
        );
        for needle in [
            "pub struct Listable<T>",
            "pub struct StringOrObj<T>(pub T);",
        ] {
            assert!(
                !source.contains(needle),
                "expected ir/mod.rs to stop owning `{needle}`"
            );
        }
    }
}
