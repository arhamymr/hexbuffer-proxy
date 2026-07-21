//! Compile-time version information derived from git (via vergen).

/// Output of `git describe --tags --always --dirty`.
/// e.g. `"v0.0.1"`, `"v0.0.1-3-gabc1234"`, `"v0.0.1-dirty"`.
pub const GIT_VERSION: &str = env!("VERGEN_GIT_DESCRIBE");

/// Full commit SHA.
pub const GIT_SHA: &str = env!("VERGEN_GIT_SHA");

/// `"true"` if the working tree had uncommitted changes at build time.
pub const GIT_DIRTY: &str = env!("VERGEN_GIT_DIRTY");
