use std::{fs::File, io, path::Path};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    atomic_replace, create_dirs, lease_file, open_identity, open_read, private_dir, remove_file,
    transform_in_place,
};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    atomic_replace, create_dirs, lease_file, open_identity, open_read, private_dir, remove_file,
    transform_in_place,
};

fn rejected(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn open_regular(path: &Path, open: impl FnOnce(&Path) -> io::Result<File>) -> io::Result<File> {
    let file = open(path)?;
    if !file.metadata()?.is_file() {
        return Err(rejected("expected a regular file"));
    }
    Ok(file)
}

pub fn open_trusted(path: &Path) -> anyhow::Result<File> {
    #[cfg(unix)]
    let file = open_read(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        let owner = rustix::process::geteuid().as_raw();
        anyhow::ensure!(
            (metadata.uid() == owner || metadata.uid() == 0) && metadata.mode() & 0o022 == 0,
            "trusted file has unsafe owner or permissions"
        );
    }
    #[cfg(windows)]
    let file = open_identity(path)?;
    Ok(file)
}

pub fn read_trusted(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    crate::common::bounded(open_trusted(path)?, limit)
}
