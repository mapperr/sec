use std::{
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem::{offset_of, size_of},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsValidSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle,
    },
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use super::{open_regular, rejected};

pub fn open_read(path: &Path) -> io::Result<File> {
    let _parents = ancestors(parent(path)?, false)?;
    open_regular(path, |path| {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // The File owns the handle and info is a writable Win32 output buffer.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.nNumberOfLinks != 1 {
            return Err(rejected("refusing a reparse point or multiply linked file"));
        }
        Ok(file)
    })
}

fn current_user() -> io::Result<Vec<usize>> {
    let mut raw = ptr::null_mut();
    // OpenProcessToken returns an owned token handle if successful.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut size,
        )
    };
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || size < size_of::<TOKEN_USER>() as u32
    {
        return Err(error);
    }
    let mut user = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(user)
}

struct SecurityDescriptor(*mut c_void);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // GetSecurityInfo allocates the descriptor with LocalAlloc.
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn require_private(file: &File) -> io::Result<()> {
    let token = current_user()?;
    // The aligned token buffer contains a TOKEN_USER and the SID it references.
    let user = unsafe { (*token.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut owner: PSID = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = SecurityDescriptor(ptr::null_mut());
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor.0,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if owner.is_null()
        || acl.is_null()
        || unsafe {
            EqualSid(owner, user) == 0
                && IsWellKnownSid(owner, WinLocalSystemSid) == 0
                && IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == 0
        }
    {
        return Err(rejected(
            "identity or directory needs a trusted owner and a private DACL",
        ));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            acl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    for index in 0..information.AceCount {
        let mut entry = ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Only ordinary allow ACEs can be safely classified here. DACLs with
        // other ACE formats need a separate security policy.
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(rejected(
                "identity DACL contains an unsupported access rule",
            ));
        }
        let sid = unsafe {
            entry
                .cast::<u8>()
                .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                .cast()
        };
        let allowed = unsafe {
            IsValidSid(sid) != 0
                && (EqualSid(sid, user) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0)
        };
        if !allowed {
            return Err(rejected("identity DACL grants access to another account"));
        }
    }
    Ok(())
}

pub fn open_identity(path: &Path) -> io::Result<File> {
    let file = open_read(path)?;
    require_private(&file)?;
    Ok(file)
}

fn directory_handle(path: &Path) -> io::Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(dir.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !dir.metadata()?.is_dir() || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(rejected("expected a real directory and no reparse point"));
    }
    Ok(dir)
}

fn ancestors(path: &Path, create: bool) -> io::Result<Vec<File>> {
    let path = std::path::absolute(path)?;
    let mut stack = Vec::new();
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => current.push(part.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(rejected("parent traversal in a managed file path"));
            }
            Component::Normal(name) => {
                current.push(name);
                let dir = match directory_handle(&current) {
                    Ok(dir) => dir,
                    Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                        match fs::create_dir(&current) {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(error) => return Err(error),
                        }
                        directory_handle(&current)?
                    }
                    Err(error) => return Err(error),
                };
                stack.push(dir);
            }
        }
    }
    if stack.is_empty() {
        stack.push(directory_handle(&path)?);
    }
    Ok(stack)
}

pub fn private_dir(path: &Path) -> io::Result<File> {
    let file = ancestors(path, false)?
        .pop()
        .ok_or_else(|| rejected("missing directory"))?;
    require_private(&file)?;
    Ok(file)
}

pub fn create_dirs(path: &Path) -> io::Result<()> {
    ancestors(path, true).map(|_| ())
}

fn parent(path: &Path) -> io::Result<&Path> {
    let parent = path
        .parent()
        .ok_or_else(|| rejected("path has no parent"))?;
    Ok(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })
}

struct WriteLock(OwnedHandle);

impl Drop for WriteLock {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::System::Threading::ReleaseMutex(self.0.as_raw_handle()) };
    }
}

fn write_lock(path: &Path) -> io::Result<WriteLock> {
    use windows_sys::Win32::{
        Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0},
        System::Threading::{CreateMutexW, WaitForSingleObject},
    };
    let path = fs::canonicalize(path)?;
    let name = format!(
        "Local\\sec-{}",
        crate::common::sha(path.to_string_lossy().to_lowercase())
    );
    let name = name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let raw = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), 10_000) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(WriteLock(handle)),
        _ => Err(io::Error::other(
            "timed out locking the destination directory",
        )),
    }
}

pub fn atomic_replace(path: &Path, expected: Option<&[u8]>, data: &[u8]) -> anyhow::Result<()> {
    let parent = parent(path)?;
    let handles = ancestors(parent, false)?;
    require_private(handles.last().unwrap())?;
    let _lock = write_lock(parent)?;
    match (open_read(path), expected) {
        (Err(error), None) if error.kind() == io::ErrorKind::NotFound => {}
        (Ok(file), Some(value)) => {
            let mut current = Vec::new();
            file.take(value.len() as u64 + 1)
                .read_to_end(&mut current)?;
            if current != value {
                anyhow::bail!("destination changed during operation");
            }
        }
        (Err(error), _) => return Err(error.into()),
        _ => anyhow::bail!("destination appeared during operation"),
    }
    let mut output = tempfile::Builder::new()
        .prefix(".sec-")
        .tempfile_in(parent)?;
    require_private(output.as_file())?;
    output.write_all(data)?;
    output.as_file().sync_all()?;
    output.persist(path).map_err(|error| error.error)?;
    Ok(())
}

pub fn transform_in_place(
    path: &Path,
    transform: impl FnOnce(&mut File, &mut File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let parent = parent(path)?;
    let handles = ancestors(parent, false)?;
    require_private(handles.last().unwrap())?;
    let _lock = write_lock(parent)?;
    let mut source = open_read(path)?;
    let mut output = tempfile::Builder::new()
        .prefix(".sec-")
        .tempfile_in(parent)?;
    require_private(output.as_file())?;
    transform(&mut source, output.as_file_mut())?;
    output.as_file().sync_all()?;
    drop(source);
    output.persist(path).map_err(|error| error.error)?;
    Ok(())
}

pub fn remove_file(path: &Path) -> io::Result<()> {
    let handles = ancestors(parent(path)?, false)?;
    require_private(handles.last().unwrap())?;
    let _lock = write_lock(parent(path)?)?;
    drop(open_read(path)?);
    fs::remove_file(path)
}

pub fn lease_file(path: &Path) -> io::Result<File> {
    private_dir(path)?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path.join(".sec-remote-git/sec-lease"))
}
