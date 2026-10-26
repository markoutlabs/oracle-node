//! Fake nodes and registries, for testing consumers of this SDK.
//!
//! The signing fakes live in [`oracle_quorum::testing`]; this module adds a
//! registry source. **Never use these keys in production.**

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oracle_wire::Registry;

pub use oracle_quorum::testing::*;

use crate::source::{FetchError, RegistryFuture, RegistrySource};

/// Serves whatever registry the test gives it, and counts fetches.
#[derive(Default)]
pub struct TestSource {
    document: Mutex<Option<Registry>>,
    fetches: AtomicUsize,
}

impl TestSource {
    /// A source that serves `registry`.
    #[must_use]
    pub fn serving(registry: Registry) -> Arc<Self> {
        Arc::new(Self {
            document: Mutex::new(Some(registry)),
            fetches: AtomicUsize::new(0),
        })
    }

    /// Serves `registry` from the next fetch on.
    ///
    /// # Panics
    ///
    /// Panics if a fetch panicked while holding the lock.
    pub fn serve(&self, registry: Registry) {
        *self.document.lock().expect("not poisoned") = Some(registry);
    }

    /// How many fetches were made.
    #[must_use]
    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl RegistrySource for TestSource {
    fn fetch(&self) -> RegistryFuture<'_> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let document = self.document.lock().expect("not poisoned").clone();
        Box::pin(async move {
            document.ok_or_else(|| FetchError::Transport("nothing to serve".to_owned()))
        })
    }
}
