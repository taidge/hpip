use std::fs::{File, Metadata};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, SetFileTime};

/// Get windows-style attributes for the specified file
pub fn win32_file_attributes(_: &Metadata, path: &Path) -> u32 {
    use std::os::windows::ffi::OsStrExt;
    let mut buf: Vec<u16> = path.as_os_str().encode_wide().collect();
    buf.push(0);
    unsafe { GetFileAttributesW(buf.as_ptr()) }
}

/// ETag based on file size, creation time, and last write time
pub fn file_etag(m: &Metadata) -> String {
    format!(
        "{:x}-{}-{}",
        m.file_size(),
        m.creation_time(),
        m.last_write_time()
    )
}

/// Check if file is marked executable
#[inline(always)]
pub fn file_executable(_: &Metadata) -> bool {
    true
}

pub fn set_executable(_: &Path, _: bool) {}

pub fn set_mtime(f: &Path, ms: u64) {
    set_times(f, Some(ms), None, None)
}

pub fn set_mtime_f(f: &File, ms: u64) {
    set_times_f(f, Some(ms), None, None)
}

const NO_FILETIME: FILETIME = FILETIME {
    dwLowDateTime: 0,
    dwHighDateTime: 0,
};

pub fn set_times_f(f: &File, mtime_ms: Option<u64>, atime_ms: Option<u64>, ctime_ms: Option<u64>) {
    if mtime_ms.is_some() || atime_ms.is_some() || ctime_ms.is_some() {
        unsafe {
            SetFileTime(
                f.as_raw_handle() as _,
                &ctime_ms.map(ms_to_filetime).unwrap_or(NO_FILETIME),
                &atime_ms.map(ms_to_filetime).unwrap_or(NO_FILETIME),
                &mtime_ms.map(ms_to_filetime).unwrap_or(NO_FILETIME),
            );
        }
    }
}

pub fn set_times(f: &Path, mtime_ms: Option<u64>, atime_ms: Option<u64>, ctime_ms: Option<u64>) {
    if mtime_ms.is_some() || atime_ms.is_some() || ctime_ms.is_some() {
        if let Ok(f) = File::options().write(true).open(f) {
            set_times_f(&f, mtime_ms, atime_ms, ctime_ms);
        }
    }
}

/// FILETIME is in increments of 100ns, and in the Win32 epoch
fn ms_to_filetime(ms: u64) -> FILETIME {
    let ft = (ms * 10_000) + 116444736000000000;
    FILETIME {
        dwLowDateTime: (ft & 0xFFFFFFFF) as u32,
        dwHighDateTime: (ft >> 32) as u32,
    }
}
