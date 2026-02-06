use chrono::{DateTime, Utc};
use std::fs::Metadata;
use std::path::Path;
use std::time::{Instant, SystemTime};

/// Get the timestamp of the file's last modification as a `chrono::DateTime`.
pub fn file_time_modified_p(f: &Path) -> DateTime<Utc> {
    file_time_modified(&f.metadata().expect("Failed to get file metadata"))
}

/// Get the timestamp of the file's creation as a `chrono::DateTime`.
pub fn file_time_created_p(f: &Path) -> DateTime<Utc> {
    file_time_created(&f.metadata().expect("Failed to get file metadata"))
}

/// Get the timestamp of the file's last access as a `chrono::DateTime`.
pub fn file_time_accessed_p(f: &Path) -> DateTime<Utc> {
    file_time_accessed(&f.metadata().expect("Failed to get file metadata"))
}

/// Get the timestamp of the file's last modification as a `chrono::DateTime`.
pub fn file_time_modified(m: &Metadata) -> DateTime<Utc> {
    file_time_impl(m.modified().expect("Failed to get file last modified date"))
}

/// Get the timestamp of the file's creation as a `chrono::DateTime`.
pub fn file_time_created(m: &Metadata) -> DateTime<Utc> {
    file_time_impl(
        m.created()
            .or_else(|_| m.modified())
            .expect("Failed to get file created date"),
    )
}

/// Get the timestamp of the file's last access as a `chrono::DateTime`.
pub fn file_time_accessed(m: &Metadata) -> DateTime<Utc> {
    file_time_impl(m.accessed().expect("Failed to get file accessed date"))
}

fn file_time_impl(time: SystemTime) -> DateTime<Utc> {
    match time.elapsed() {
        Ok(dur) => Utc::now() - dur,
        Err(ste) => Utc::now() + ste.duration(),
    }
}

/// `clock_gettime(CLOCK_MONOTONIC)` in ns
pub fn precise_time_ns() -> u64 {
    const ZERO: Instant = unsafe { std::mem::zeroed() };
    (Instant::now() - ZERO).as_nanos() as u64
}
