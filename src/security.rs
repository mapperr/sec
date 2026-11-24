use std::path::Path;

use anyhow::{Result, bail};

use crate::{git, store::Store};

pub fn cli(args: &[String]) -> Result<i32> {
    match args {
        [action, root] if action == "stage-store" => git::stage_store(&Store::local(root.into())?)?,
        [action, root, mode] if action == "pre-receive" && mode == "--store" => {
            git::pre_receive(Path::new(root), mode, "")?;
        }
        [action, root, mode, argument] if action == "pre-receive" => {
            git::pre_receive(Path::new(root), mode, argument)?;
        }
        _ => bail!("invalid security command or arguments. Run sec security --help"),
    }
    Ok(0)
}
