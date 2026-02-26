#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Mutex, OnceLock};

/// Runs `f` with temporary host environment variable overrides under a global
/// process-wide lock to avoid cross-test races.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn with_locked_host_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("host env lock should not be poisoned");

    let previous = vars
        .iter()
        .map(|(name, _)| ((*name).to_string(), std::env::var(name).ok()))
        .collect::<Vec<_>>();

    for (name, value) in vars {
        match value {
            Some(v) => {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var(name, v);
                }
            }
            None => {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::remove_var(name);
                }
            }
        }
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    for (name, value) in previous {
        match value {
            Some(v) => {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var(name, v);
                }
            }
            None => {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::remove_var(name);
                }
            }
        }
    }

    match result {
        Ok(output) => output,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
