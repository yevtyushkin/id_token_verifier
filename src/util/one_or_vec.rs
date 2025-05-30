use serde::*;

/// One value of type T or a [Vec] of values of type T.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum OneOrVec<T> {
    /// One value of type T.
    One(T),
    /// [Vec] of values of type T.
    Vec(Vec<T>),
}

impl<T> OneOrVec<T> {
    /// Whether this instance does not contain any value.
    pub fn is_empty(&self) -> bool {
        matches!(self, OneOrVec::Vec(vec) if vec.is_empty())
    }
}

impl<T> From<T> for OneOrVec<T> {
    fn from(value: T) -> OneOrVec<T> {
        OneOrVec::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrVec<T> {
    fn from(value: Vec<T>) -> OneOrVec<T> {
        OneOrVec::Vec(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_or_vec_is_empty() {
        assert_eq!(OneOrVec::One(()).is_empty(), false);

        assert_eq!(OneOrVec::Vec(vec![()]).is_empty(), false);

        assert_eq!(OneOrVec::Vec::<()>(vec![]).is_empty(), true);
    }
}
