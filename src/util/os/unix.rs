use std::fs::{self, File, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use libc::{AT_FDCWD, AT_SYMLINK_NOFOLLOW, UTIME_OMIT, futimens, timespec, utimensat};

use super::super::file::is_actually_file;

const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

/// Get windows-style attributes for the specified file (emulated on Unix)
pub fn win32_file_attributes(meta: &Metadata, path: &Path) -> u32 {
    let mut attr = 0;

    if meta.permissions().readonly() {
        attr |= FILE_ATTRIBUTE_READONLY;
    }

    if path
        .file_name()
        .map(|n| n.as_bytes().starts_with(b"."))
        .unwrap_or(false)
    {
        attr |= FILE_ATTRIBUTE_HIDDEN;
    }

    if !is_actually_file(&meta.file_type(), path) {
        attr |= FILE_ATTRIBUTE_DIRECTORY;
    } else {
        attr |= FILE_ATTRIBUTE_ARCHIVE;
    }

    attr
}

/// `st_dev`-`st_ino`-`st_mtime`
pub fn file_etag(m: &Metadata) -> String {
    format!("{:x}-{}-{}.{}", m.dev(), m.ino(), m.mtime(), m.mtime_nsec())
}

/// Check if file is marked executable
pub fn file_executable(meta: &Metadata) -> bool {
    (meta.permissions().mode() & 0o111) != 0
}

pub fn set_executable(f: &Path, ex: bool) {
    let mut perm = match fs::metadata(f) {
        Ok(meta) => meta.permissions(),
        Err(_) => return,
    };
    if ex {
        // Get umask to determine which execute bits to set
        let umask = unsafe {
            let old = libc::umask(0o777);
            libc::umask(old);
            old as u32
        };
        perm.set_mode(perm.mode() | (0o111 & !umask));
    } else {
        perm.set_mode(perm.mode() & !0o111);
    }
    let _ = fs::set_permissions(f, perm);
}

pub fn set_mtime(f: &Path, ms: u64) {
    set_times(f, Some(ms), None, None)
}

pub fn set_mtime_f(f: &File, ms: u64) {
    set_times_f(f, Some(ms), None, None)
}

const NO_TIMESPEC: timespec = timespec {
    tv_sec: 0,
    tv_nsec: UTIME_OMIT,
};

pub fn set_times_f(f: &File, mtime_ms: Option<u64>, atime_ms: Option<u64>, _: Option<u64>) {
    if mtime_ms.is_some() || atime_ms.is_some() {
        unsafe {
            futimens(
                f.as_raw_fd(),
                [
                    atime_ms.map(ms_to_timespec).unwrap_or(NO_TIMESPEC),
                    mtime_ms.map(ms_to_timespec).unwrap_or(NO_TIMESPEC),
                ]
                .as_ptr(),
            );
        }
    }
}

pub fn set_times(f: &Path, mtime_ms: Option<u64>, atime_ms: Option<u64>, _: Option<u64>) {
    if mtime_ms.is_some() || atime_ms.is_some() {
        unsafe {
            utimensat(
                AT_FDCWD,
                f.as_os_str().as_bytes().as_ptr() as *const _,
                [
                    atime_ms.map(ms_to_timespec).unwrap_or(NO_TIMESPEC),
                    mtime_ms.map(ms_to_timespec).unwrap_or(NO_TIMESPEC),
                ]
                .as_ptr(),
                AT_SYMLINK_NOFOLLOW,
            );
        }
    }
}

fn ms_to_timespec(ms: u64) -> timespec {
    timespec {
        tv_sec: (ms / 1000) as _,
        tv_nsec: ((ms % 1000) * 1_000_000) as _,
    }
}
