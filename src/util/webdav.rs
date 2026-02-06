use std::fmt;
use std::fs;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::path::Path;

use walkdir::WalkDir;
use xml::name::Name as XmlName;

use super::file::is_actually_file;

macro_rules! xml_name {
    ($ns:expr, $ln:expr) => {
        XmlName {
            local_name: $ln,
            namespace: Some($ns.1),
            prefix: Some($ns.0),
        }
    };
}

/// Prefix and namespace URI for generic WebDAV elements
pub const WEBDAV_XML_NAMESPACE_DAV: (&str, &str) = ("D", "DAV:");

/// Prefix and namespace URI for elements specific to Windows clients
pub const WEBDAV_XML_NAMESPACE_MICROSOFT: (&str, &str) = ("Z", "urn:schemas-microsoft-com:");

/// Prefix and namespace URI for elements for Apache emulation
pub const WEBDAV_XML_NAMESPACE_APACHE: (&str, &str) = ("A", "http://apache.org/dav/props/");

/// All first-class-recognised prefix/namespace pairs.
/// `WEBDAV_XML_NAMESPACE_DAV` needs to be the first here.
pub const WEBDAV_XML_NAMESPACES: &[(&str, &str)] = &[
    WEBDAV_XML_NAMESPACE_DAV,
    WEBDAV_XML_NAMESPACE_MICROSOFT,
    WEBDAV_XML_NAMESPACE_APACHE,
];

/// Properties to return on empty body or `<allprop />` for non-Windows clients
pub const WEBDAV_ALLPROP_PROPERTIES_NON_WINDOWS: &[&[XmlName<'_>]] = &[&[
    xml_name!(WEBDAV_XML_NAMESPACE_DAV, "creationdate"),
    xml_name!(WEBDAV_XML_NAMESPACE_DAV, "getcontentlength"),
    xml_name!(WEBDAV_XML_NAMESPACE_DAV, "getcontenttype"),
    xml_name!(WEBDAV_XML_NAMESPACE_DAV, "getlastmodified"),
    xml_name!(WEBDAV_XML_NAMESPACE_DAV, "resourcetype"),
]];

/// Properties to return on empty body or `<allprop />` for Windows clients
pub const WEBDAV_ALLPROP_PROPERTIES_WINDOWS: &[&[XmlName<'_>]] = &[
    WEBDAV_ALLPROP_PROPERTIES_NON_WINDOWS[0],
    &[
        xml_name!(WEBDAV_XML_NAMESPACE_MICROSOFT, "Win32CreationTime"),
        xml_name!(WEBDAV_XML_NAMESPACE_MICROSOFT, "Win32FileAttributes"),
        xml_name!(WEBDAV_XML_NAMESPACE_MICROSOFT, "Win32LastAccessTime"),
        xml_name!(WEBDAV_XML_NAMESPACE_MICROSOFT, "Win32LastModifiedTime"),
    ],
];

/// Properties listed for a `<propname />` request
pub const WEBDAV_PROPNAME_PROPERTIES: &[&[XmlName<'_>]] = &[
    WEBDAV_ALLPROP_PROPERTIES_NON_WINDOWS[0],
    &[
        xml_name!(WEBDAV_XML_NAMESPACE_APACHE, "executable"),
        xml_name!(WEBDAV_XML_NAMESPACE_MICROSOFT, "Win32LastAccessTime"),
    ],
];

/// The WebDAV Depth header
#[derive(Debug, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub enum Depth {
    Zero,
    One,
    Infinity,
}

impl Depth {
    /// Get a depth lower than this one by one, if it exists
    pub fn lower(self) -> Option<Depth> {
        match self {
            Depth::Zero => None,
            Depth::One => Some(Depth::Zero),
            Depth::Infinity => Some(Depth::Infinity),
        }
    }

    /// Parse from a header value string
    pub fn parse(s: &str) -> Option<Depth> {
        match s.trim() {
            "0" => Some(Depth::Zero),
            "1" => Some(Depth::One),
            "infinity" | "Infinity" => Some(Depth::Infinity),
            _ => None,
        }
    }
}

impl fmt::Display for Depth {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Depth::Zero => f.write_str("0"),
            Depth::One => f.write_str("1"),
            Depth::Infinity => f.write_str("infinity"),
        }
    }
}

/// The WebDAV Overwrite header
#[derive(Debug, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct Overwrite(pub bool);

impl Default for Overwrite {
    fn default() -> Overwrite {
        Overwrite(true)
    }
}

impl Overwrite {
    pub fn parse(s: &str) -> Option<Overwrite> {
        match s.trim() {
            "T" => Some(Overwrite(true)),
            "F" => Some(Overwrite(false)),
            _ => None,
        }
    }
}

/// Check if a User-Agent header indicates a Microsoft client
pub fn client_microsoft(user_agent: Option<&str>) -> bool {
    user_agent
        .map(|s| s.contains("Microsoft") || s.contains("microsoft"))
        .unwrap_or(false)
}

/// Copy a directory recursively from `from` to `to`.
pub fn copy_dir(from: &Path, to: &Path) -> IoResult<Vec<(IoError, String)>> {
    fs::create_dir(to)?;

    // Disallow copying a directory into itself
    if from
        .canonicalize()
        .and_then(|fc| to.canonicalize().map(|tc| (fc, tc)))
        .map(|(fc, tc)| tc.starts_with(fc))?
    {
        fs::remove_dir(to)?;
        return Err(IoError::new(
            IoErrorKind::Other,
            "cannot copy to a path prefixed by the source path",
        ));
    }

    let mut errors = Vec::new();
    for entry in WalkDir::new(from).min_depth(1).into_iter().flatten() {
        let source_metadata = match entry.metadata() {
            Ok(md) => md,
            Err(err) => {
                errors.push((err.into(), entry.path().to_string_lossy().into_owned()));
                continue;
            }
        };

        let relative_path = entry
            .path()
            .strip_prefix(from)
            .expect("strip_prefix failed");
        let target_path = to.join(relative_path);

        if !is_actually_file(&source_metadata.file_type(), entry.path()) {
            if let Err(e) = fs::create_dir(&target_path) {
                errors.push((e, relative_path.to_string_lossy().into_owned()));
            }
            if let Err(e) = fs::set_permissions(&target_path, source_metadata.permissions()) {
                errors.push((e, relative_path.to_string_lossy().into_owned()));
            }
        } else if let Err(e) = fs::copy(entry.path(), &target_path) {
            errors.push((e, relative_path.to_string_lossy().into_owned()));
        }
    }

    Ok(errors)
}

/// Parse a Win32 time string to ms since epoch
pub fn win32time(t: &str) -> Option<u64> {
    let tm = chrono::DateTime::parse_from_str(t, "%a, %d %b %Y %T %Z").ok()?;
    Some(tm.timestamp_millis() as u64)
}
