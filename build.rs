//! Build script — embeds git metadata via vergen.
//!
//! Exposes the standard `VERGEN_GIT_*` env vars:
//! - `VERGEN_GIT_DESCRIBE` — `git describe --tags --always --dirty`
//! - `VERGEN_GIT_SHA`     — full commit hash
//! - `VERGEN_GIT_DIRTY`   — `"true"` or `"false"`

use vergen_gitcl::{Emitter, GitclBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gitcl = GitclBuilder::all_git()?;
    Emitter::default()
        .add_instructions(&gitcl)?
        .emit()?;
    Ok(())
}
