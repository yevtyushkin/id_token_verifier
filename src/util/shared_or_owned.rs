use std::ops::Deref;
use std::sync::Arc;

/// Shared (via [Arc]) or owned value [T].
pub(crate) enum SharedOrOwned<T> {
    /// Shared value.
    Shared(Arc<T>),

    /// Owned value.
    Owned(T),
}

impl<T> Deref for SharedOrOwned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            SharedOrOwned::Shared(arc) => arc,
            SharedOrOwned::Owned(value) => value,
        }
    }
}
