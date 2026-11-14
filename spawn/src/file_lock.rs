//! Advisory lock shared with Client2: byte zero on Windows, flock on Unix.
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
    time::{Duration, Instant},
};

pub struct FileLock {
    _file: File,
}

impl FileLock {
    pub fn acquire(path: &Path, timeout: Duration) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        let started = Instant::now();
        loop {
            match try_lock(&file) {
                Ok(()) => return Ok(Self { _file: file }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if started.elapsed() >= timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "another host is installing Runtime",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(windows)]
fn try_lock(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::LockFile;
    // SAFETY: the live file owns the handle, and the one-byte range is fixed.
    if unsafe { LockFile(file.as_raw_handle(), 0, 0, 1, 0) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(33) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Err(error)
}

#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: the file keeps its descriptor valid for the entire lock lifetime.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}
