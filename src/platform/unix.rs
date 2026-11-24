use std::{
    ffi::OsStr,
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FlockOperation, Mode, OFlags},
};

use super::{open_regular, rejected};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let path = std::path::absolute(path)?;
    let mut directory = fs::open("/", DIRECTORY, Mode::empty())?;
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = fs::openat(&directory, name, DIRECTORY, Mode::empty())?;
                let info = fs::fstat(&directory)?;
                let owner = rustix::process::geteuid().as_raw();
                if (info.st_uid != 0 && info.st_uid != owner)
                    || (info.st_mode & 0o022 != 0 && info.st_mode & 0o1000 == 0)
                {
                    return Err(rejected(
                        "untrusted ownership or permissions on parent directory",
                    ));
                }
            }
            _ => return Err(rejected("parent traversal in a managed file path")),
        }
    }
    Ok(directory)
}

fn parent_and_name(path: &Path) -> io::Result<(OwnedFd, &OsStr)> {
    let parent = path
        .parent()
        .ok_or_else(|| rejected("path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| rejected("path has no filename"))?;
    Ok((
        open_directory(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })?,
        name,
    ))
}

fn require_single_link(metadata: &Metadata) -> io::Result<()> {
    if metadata.nlink() != 1 {
        return Err(rejected("refusing a multiply linked file"));
    }
    Ok(())
}

pub fn open_read(path: &Path) -> io::Result<File> {
    open_regular(path, |path| {
        let (parent, name) = parent_and_name(path)?;
        let file = File::from(fs::openat(&parent, name, READ, Mode::empty())?);
        require_single_link(&file.metadata()?)?;
        Ok(file)
    })
}

pub fn open_identity(path: &Path) -> io::Result<File> {
    let file = open_read(path)?;
    let info = file.metadata()?;
    if info.uid() != rustix::process::geteuid().as_raw() || info.mode() & 0o077 != 0 {
        return Err(rejected(
            "identity must be private and owned by the current user",
        ));
    }
    Ok(file)
}

struct Temporary<'a> {
    parent: &'a OwnedFd,
    name: String,
    file: File,
}

impl Temporary<'_> {
    fn create(parent: &OwnedFd) -> io::Result<Temporary<'_>> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
        let name = format!(".sec-{:032x}.tmp", u128::from_be_bytes(nonce));
        let fd = fs::openat(
            parent,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let output = Temporary {
            parent,
            name,
            file: File::from(fd),
        };
        fs::fchmod(&output.file, Mode::RUSR | Mode::WUSR)?;
        Ok(output)
    }
}

impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        let _ = fs::unlinkat(self.parent, self.name.as_str(), AtFlags::empty());
    }
}

pub fn transform_in_place(
    path: &Path,
    transform: impl FnOnce(&mut File, &mut File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let (parent, name) = parent_and_name(path)?;
    fs::flock(&parent, FlockOperation::LockExclusive)?;
    let mut input = File::from(fs::openat(&parent, name, READ, Mode::empty())?);
    let before = input.metadata()?;
    if !before.is_file() {
        return Err(rejected("expected a regular file").into());
    }
    require_single_link(&before)?;
    let mut output = Temporary::create(&parent)?;
    transform(&mut input, &mut output.file)?;
    output.file.sync_all()?;
    let current = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if !same_file(&before, &current) {
        return Err(rejected("input changed during processing").into());
    }
    fs::renameat(&parent, output.name.as_str(), &parent, name)?;
    #[cfg(target_os = "linux")]
    fs::fsync(&parent)?;
    Ok(())
}

pub fn private_dir(path: &Path) -> io::Result<File> {
    let file = File::from(open_directory(path)?);
    let metadata = file.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(rejected(
            "directory must be private and owned by the current user",
        ));
    }
    Ok(file)
}

pub fn create_dirs(path: &Path) -> io::Result<()> {
    let path = std::path::absolute(path)?;
    let mut directory = fs::open("/", DIRECTORY, Mode::empty())?;
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let next = match fs::openat(&directory, name, DIRECTORY, Mode::empty()) {
                    Ok(next) => next,
                    Err(rustix::io::Errno::NOENT) => {
                        match fs::mkdirat(&directory, name, Mode::RWXU) {
                            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                            Err(error) => return Err(error.into()),
                        }
                        fs::openat(&directory, name, DIRECTORY, Mode::empty())?
                    }
                    Err(error) => return Err(error.into()),
                };
                let info = fs::fstat(&next)?;
                let owner = rustix::process::geteuid().as_raw();
                if (info.st_uid != 0 && info.st_uid != owner)
                    || (info.st_mode & 0o022 != 0 && info.st_mode & 0o1000 == 0)
                {
                    return Err(rejected("untrusted directory ownership or permissions"));
                }
                directory = next;
            }
            _ => return Err(rejected("parent traversal in a managed file path")),
        }
    }
    Ok(())
}

pub fn atomic_replace(path: &Path, expected: Option<&[u8]>, data: &[u8]) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let (parent, name) = parent_and_name(path)?;
    fs::flock(&parent, FlockOperation::LockExclusive)?;
    let original = match fs::openat(&parent, name, READ, Mode::empty()) {
        Ok(fd) => {
            let file = File::from(fd);
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(rejected("expected a regular destination").into());
            }
            require_single_link(&metadata)?;
            let Some(value) = expected else {
                return Err(rejected("destination appeared during operation").into());
            };
            let mut current = Vec::new();
            file.take(value.len() as u64 + 1)
                .read_to_end(&mut current)?;
            if current != value {
                return Err(rejected("destination changed during operation").into());
            }
            Some(metadata)
        }
        Err(rustix::io::Errno::NOENT) if expected.is_none() => None,
        Err(error) => return Err(error.into()),
    };
    let mut output = Temporary::create(&parent)?;
    output.file.write_all(data)?;
    output.file.sync_all()?;
    let current = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW);
    let unchanged = match (original, current) {
        (None, Err(rustix::io::Errno::NOENT)) => true,
        (Some(before), Ok(after)) => same_file(&before, &after),
        _ => false,
    };
    if !unchanged {
        return Err(rejected("destination changed during operation").into());
    }
    fs::renameat(&parent, output.name.as_str(), &parent, name)?;
    #[cfg(target_os = "linux")]
    fs::fsync(&parent)?;
    Ok(())
}

#[allow(clippy::unnecessary_cast)] // Apple and Linux use different widths for stat fields.
fn same_file(before: &Metadata, after: &fs::Stat) -> bool {
    after.st_dev as u64 == before.dev()
        && after.st_ino as u64 == before.ino()
        && after.st_ctime as i64 == before.ctime()
        && after.st_ctime_nsec as i64 == before.ctime_nsec()
        && after.st_size as u64 == before.len()
        && after.st_nlink == 1
}

pub fn remove_file(path: &Path) -> io::Result<()> {
    let (parent, name) = parent_and_name(path)?;
    fs::flock(&parent, FlockOperation::LockExclusive)?;
    let source = File::from(fs::openat(&parent, name, READ, Mode::empty())?);
    let metadata = source.metadata()?;
    if !metadata.is_file() {
        return Err(rejected("expected a regular file"));
    }
    require_single_link(&metadata)?;
    fs::unlinkat(&parent, name, AtFlags::empty())?;
    Ok(())
}

pub fn lease_file(path: &Path) -> io::Result<File> {
    open_directory(path).map(File::from)
}
