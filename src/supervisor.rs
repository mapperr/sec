use anyhow::Result;
use std::{fs::File, process::Command};

#[cfg(target_os = "linux")]
pub fn program(path: &str, pinned: Option<&File>) -> String {
    use std::os::fd::AsRawFd;
    pinned.map_or_else(
        || path.to_owned(),
        |file| format!("/proc/self/fd/{}", file.as_raw_fd()),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn program(path: &str, _pinned: Option<&File>) -> String {
    path.to_owned()
}

#[cfg(unix)]
pub fn spawn(command: &mut Command, lease: &File, pinned: Option<&File>) -> Result<i32> {
    use anyhow::Context;
    use rustix::{
        process::{Pid, kill_process_group},
        termios::{tcgetpgrp, tcsetpgrp},
    };
    use signal_hook::{
        consts::signal::{SIGHUP, SIGINT, SIGTERM},
        flag, low_level,
    };
    use std::{
        os::{
            fd::AsRawFd,
            unix::process::{CommandExt, ExitStatusExt},
        },
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    let signal = Arc::new(AtomicUsize::new(0));
    let mut signals = Vec::new();
    for number in [SIGHUP, SIGINT, SIGTERM] {
        signals.push(flag::register_usize(
            number,
            signal.clone(),
            number as usize,
        )?);
    }
    let lease = lease.as_raw_fd();
    let pinned = pinned.map(AsRawFd::as_raw_fd);
    // Only async-signal-safe descriptor operations run between fork and exec.
    unsafe {
        command.process_group(0).pre_exec(move || {
            for fd in std::iter::once(lease).chain(pinned) {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("launch approved command")?;
    let group = Pid::from_raw(child.id() as i32).context("child has no process group")?;
    let tty = crate::common::terminal().ok().map(|(_, output)| output);
    let foreground = rustix::process::getpgrp();
    let handoff = tty
        .as_ref()
        .filter(|tty| tcgetpgrp(*tty).is_ok_and(|id| id == foreground));
    // A supervisor in the background must be able to restore foreground control.
    let previous = if handoff.is_some() {
        Some(unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) })
    } else {
        None
    };
    if let Some(tty) = handoff
        && tcsetpgrp(tty, group).is_ok()
    {
        let _ = kill_process_group(group, rustix::process::Signal::CONT);
    }
    let result = (|| -> Result<i32> {
        let mut deadline = None;
        loop {
            if let Some(status) = child.try_wait()? {
                let number = signal.load(Ordering::Relaxed) as i32;
                return Ok(if number != 0 {
                    128 + number
                } else {
                    status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
                });
            }
            let number = signal.load(Ordering::Relaxed);
            if number != 0 && deadline.is_none() {
                if let Some(signal) = rustix::process::Signal::from_named_raw(number as i32) {
                    let _ = kill_process_group(group, signal);
                }
                deadline = Some(Instant::now() + Duration::from_secs(5));
            } else if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                let _ = kill_process_group(group, rustix::process::Signal::KILL);
                child.wait()?;
                return Ok(128 + number as i32);
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    let _ = kill_process_group(group, rustix::process::Signal::KILL);
    let _ = child.wait();
    if let Some(tty) = handoff {
        let _ = tcsetpgrp(tty, foreground);
    }
    if let Some(previous) = previous {
        unsafe { libc::signal(libc::SIGTTOU, previous) };
    }
    for id in signals {
        low_level::unregister(id);
    }
    result
}

#[cfg(windows)]
pub fn spawn(command: &mut Command, _lease: &File, _pinned: Option<&File>) -> Result<i32> {
    use std::{
        io,
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
    let mut process = command.creation_flags(CREATE_SUSPENDED).spawn()?;
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let err = io::Error::last_os_error();
        let _ = process.kill();
        let _ = process.wait();
        return Err(err.into());
    }
    if let Err(error) = resume_primary(process.id()) {
        let _ = process.kill();
        let _ = process.wait();
        return Err(error);
    }
    Ok(process.wait()?.code().unwrap_or(1))
}

#[cfg(windows)]
fn resume_primary(pid: u32) -> Result<()> {
    use std::{
        io,
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            Threading::{GetCurrentThreadId, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    let source = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut ok = unsafe { Thread32First(source.as_raw_handle(), &mut entry) };
    let mut primary = None;
    while ok != 0 {
        if entry.th32OwnerProcessID == pid {
            anyhow::ensure!(
                primary.replace(entry.th32ThreadID).is_none(),
                "suspended process has multiple threads"
            );
        }
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        ok = unsafe { Thread32Next(source.as_raw_handle(), &mut entry) };
    }
    let id = primary.ok_or_else(|| anyhow::anyhow!("suspended primary thread not found"))?;
    anyhow::ensure!(
        id != unsafe { GetCurrentThreadId() },
        "invalid suspended primary thread"
    );
    let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, id) };
    if raw.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
    anyhow::ensure!(
        unsafe { ResumeThread(thread.as_raw_handle()) } == 1,
        "cannot resume the suspended primary thread"
    );
    Ok(())
}
