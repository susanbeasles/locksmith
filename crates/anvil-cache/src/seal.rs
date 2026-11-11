use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::error::CacheError;

const MAX_RELATIVE_PATH_LEN: usize = 512;
const STREAM_CHUNK_BYTES: usize = 16_384;

/// Kernel file-sealing enforcement policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SealPolicy {
    /// Fail closed (`CacheError::SealFailed`) on Linux if `memfd_create` or
    /// `fcntl_add_seals` fails for any reason.
    #[default]
    RequireKernelMemfd,
    /// Explicit opt-in fallback to a private verified `Arc<[u8]>` in RAM for
    /// restricted test sandboxes where `memfd_create` is unavailable.
    AllowUnsealedFallback,
}

#[derive(Debug)]
enum SealedBacking {
    #[cfg(target_os = "linux")]
    Memfd {
        fd: rustix::fd::OwnedFd,
        len: usize,
        digest: [u8; 32],
    },
    Memory {
        bytes: Arc<[u8]>,
        digest: [u8; 32],
    },
}

/// Read-only cache payload verified in RAM and sealed at the kernel descriptor
/// level (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`) on Linux.
#[derive(Debug)]
pub struct VerifiedReadOnlyBlob {
    backing: SealedBacking,
}

impl VerifiedReadOnlyBlob {
    /// Returns the verified 32-byte `BLAKE3` content digest.
    #[must_use]
    pub fn content_digest(&self) -> &[u8; 32] {
        match &self.backing {
            #[cfg(target_os = "linux")]
            SealedBacking::Memfd { digest, .. } => digest,
            SealedBacking::Memory { digest, .. } => digest,
        }
    }

    /// Returns the verified byte length of the sealed payload.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.backing {
            #[cfg(target_os = "linux")]
            SealedBacking::Memfd { len, .. } => *len,
            SealedBacking::Memory { bytes, .. } => bytes.len(),
        }
    }

    /// Returns `true` if the sealed payload has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` when backed by a Linux kernel-sealed `memfd`.
    #[must_use]
    pub fn is_kernel_sealed(&self) -> bool {
        match &self.backing {
            #[cfg(target_os = "linux")]
            SealedBacking::Memfd { .. } => true,
            SealedBacking::Memory { .. } => false,
        }
    }

    /// Exposes the borrowed `memfd` descriptor on Linux for zero-copy read or seal inspection.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_sealed_fd(&self) -> Option<rustix::fd::BorrowedFd<'_>> {
        use rustix::fd::AsFd;
        match &self.backing {
            SealedBacking::Memfd { fd, .. } => Some(fd.as_fd()),
            SealedBacking::Memory { .. } => None,
        }
    }

    /// Reads a fresh byte vector from the sealed backing without advancing shared cursor state,
    /// using fallible heap reservation so oversized blobs cannot abort on OOM.
    pub fn read_to_vec(&self) -> Result<Vec<u8>, CacheError> {
        match &self.backing {
            #[cfg(target_os = "linux")]
            SealedBacking::Memfd { fd, len, .. } => pread_exact_vec(fd, *len),
            SealedBacking::Memory { bytes, .. } => {
                let mut out = Vec::new();
                out.try_reserve_exact(bytes.len())
                    .map_err(|_| CacheError::IoError)?;
                out.extend_from_slice(bytes);
                Ok(out)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn pread_exact_vec(fd: &rustix::fd::OwnedFd, len: usize) -> Result<Vec<u8>, CacheError> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| CacheError::IoError)?;
    out.resize(len, 0u8);
    let mut offset = 0usize;
    while offset < len {
        let pos_u64 = u64::try_from(offset).map_err(|_| CacheError::IoError)?;
        match rustix::io::pread(fd, &mut out[offset..], pos_u64) {
            Ok(0) => return Err(CacheError::IoError),
            Ok(n) => {
                offset = offset.checked_add(n).ok_or(CacheError::IoError)?;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(CacheError::IoError),
        }
    }
    Ok(out)
}

/// Validates that `relative_path` is strictly relative, free of `.` / `..`,
/// backslashes, NUL bytes, or non-safe filename bytes.
pub fn validate_relative_cache_path(relative_path: &str) -> Result<(), CacheError> {
    if relative_path.is_empty()
        || relative_path.len() > MAX_RELATIVE_PATH_LEN
        || relative_path.starts_with('/')
        || relative_path.ends_with('/')
        || relative_path.contains('\\')
        || relative_path.contains('\0')
    {
        return Err(CacheError::PathViolation);
    }

    for segment in relative_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CacheError::PathViolation);
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(CacheError::PathViolation);
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn open_anchor_root_dir(root_dir: &Path) -> Result<rustix::fd::OwnedFd, CacheError> {
    use rustix::fs::{mkdirat, open, openat2, Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;

    let root_fd = open(
        root_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|err| match err {
        Errno::LOOP | Errno::NOTDIR => CacheError::PathViolation,
        Errno::NOENT => CacheError::NotFound,
        _ => CacheError::IoError,
    })?;

    for sub in ["blobs", "index"] {
        match mkdirat(&root_fd, sub, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(Errno::LOOP | Errno::ACCESS | Errno::PERM) => {
                return Err(CacheError::PathViolation)
            }
            Err(_) => return Err(CacheError::IoError),
        }
        // Confirm subdirectory is a real directory strictly beneath root_fd (never a symlink/mount)
        let _verified_sub = openat2(
            &root_fd,
            sub,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(|err| match err {
            Errno::LOOP
            | Errno::XDEV
            | Errno::NOTDIR
            | Errno::ACCESS
            | Errno::PERM
            | Errno::INVAL => CacheError::PathViolation,
            _ => CacheError::IoError,
        })?;
    }

    Ok(root_fd)
}

#[cfg(target_os = "linux")]
pub(crate) fn open_confined_readonly_at(
    root_fd: &rustix::fd::OwnedFd,
    relative_path: &str,
) -> Result<File, CacheError> {
    use rustix::fs::{fstat, openat2, FileType, Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;

    validate_relative_cache_path(relative_path)?;

    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;

    let fd = match openat2(root_fd, relative_path, flags, Mode::empty(), resolve) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(CacheError::NotFound),
        Err(
            Errno::LOOP
            | Errno::XDEV
            | Errno::NOTDIR
            | Errno::ACCESS
            | Errno::PERM
            | Errno::INVAL
            | Errno::ISDIR,
        ) => return Err(CacheError::PathViolation),
        Err(_) => return Err(CacheError::IoError),
    };

    let st = fstat(&fd).map_err(|_| CacheError::IoError)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(CacheError::PathViolation);
    }

    Ok(File::from(fd))
}

#[cfg(target_os = "linux")]
pub(crate) fn write_confined_atomic_at(
    root_fd: &rustix::fd::OwnedFd,
    subdir: &str,
    filename: &str,
    bytes: &[u8],
) -> Result<(), CacheError> {
    use rustix::fs::{
        fsync, openat2, renameat, renameat_with, statat, unlinkat, AtFlags, FileType, Mode, OFlags,
        RenameFlags, ResolveFlags,
    };
    use rustix::io::Errno;

    if subdir.contains('/') || filename.contains('/') {
        return Err(CacheError::PathViolation);
    }
    validate_relative_cache_path(subdir)?;
    validate_relative_cache_path(filename)?;

    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
    let dir_fd = openat2(
        root_fd,
        subdir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        resolve,
    )
    .map_err(|err| match err {
        Errno::LOOP | Errno::XDEV | Errno::NOTDIR | Errno::ACCESS | Errno::PERM | Errno::INVAL => {
            CacheError::PathViolation
        }
        _ => CacheError::IoError,
    })?;

    // Reject pre-planted symlinks, directories, FIFOs, sockets, or device nodes before staging
    match statat(&dir_fd, filename, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(CacheError::PathViolation);
            }
        }
        Err(Errno::NOENT) => {}
        Err(Errno::LOOP | Errno::ACCESS | Errno::PERM) => return Err(CacheError::PathViolation),
        Err(_) => return Err(CacheError::IoError),
    }

    let mut entropy = [0u8; 12];
    aws_lc_rs::rand::fill(&mut entropy).map_err(|_| CacheError::IoError)?;
    let mut rand_hex = String::with_capacity(24);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in &entropy {
        rand_hex.push(char::from(HEX[usize::from(b >> 4)]));
        rand_hex.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    let tmp_name = format!("tmp-{rand_hex}-{filename}");
    validate_relative_cache_path(&tmp_name)?;

    let tmp_fd = openat2(
        &dir_fd,
        &tmp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
        resolve,
    )
    .map_err(|err| match err {
        Errno::LOOP | Errno::XDEV | Errno::NOTDIR | Errno::ACCESS | Errno::PERM | Errno::INVAL => {
            CacheError::PathViolation
        }
        _ => CacheError::IoError,
    })?;

    let write_res = (|| -> Result<(), CacheError> {
        let mut written = 0usize;
        while written < bytes.len() {
            match rustix::io::write(&tmp_fd, &bytes[written..]) {
                Ok(0) => return Err(CacheError::IoError),
                Ok(n) => {
                    written = written.checked_add(n).ok_or(CacheError::IoError)?;
                }
                Err(Errno::INTR) => {}
                Err(_) => return Err(CacheError::IoError),
            }
        }
        fsync(&tmp_fd).map_err(|_| CacheError::IoError)?;
        Ok(())
    })();

    drop(tmp_fd);
    if let Err(err) = write_res {
        let _ = unlinkat(&dir_fd, &tmp_name, AtFlags::empty());
        return Err(err);
    }

    // Attempt atomic NOREPLACE first; if regular file already exists, verify it is still a regular
    // file (not a raced symlink/special node) before atomic replacement.
    match renameat_with(
        &dir_fd,
        &tmp_name,
        &dir_fd,
        filename,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(Errno::EXIST) => {
            let st = match statat(&dir_fd, filename, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(s) => s,
                Err(_) => {
                    let _ = unlinkat(&dir_fd, &tmp_name, AtFlags::empty());
                    return Err(CacheError::IoError);
                }
            };
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                let _ = unlinkat(&dir_fd, &tmp_name, AtFlags::empty());
                return Err(CacheError::PathViolation);
            }
            if renameat(&dir_fd, &tmp_name, &dir_fd, filename).is_err() {
                let _ = unlinkat(&dir_fd, &tmp_name, AtFlags::empty());
                return Err(CacheError::IoError);
            }
        }
        Err(_) => {
            let _ = unlinkat(&dir_fd, &tmp_name, AtFlags::empty());
            return Err(CacheError::IoError);
        }
    }

    let _ = fsync(&dir_fd);
    Ok(())
}

/// Validates `relative_path` and opens it read-only strictly beneath `root_dir`
/// (`openat2` with `BENEATH | NO_SYMLINKS | NO_XDEV` on Linux).
pub fn open_confined_readonly(root_dir: &Path, relative_path: &str) -> Result<File, CacheError> {
    validate_relative_cache_path(relative_path)?;

    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{open, Mode, OFlags};
        use rustix::io::Errno;

        let root_fd = open(
            root_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|err| match err {
            Errno::LOOP | Errno::NOTDIR => CacheError::PathViolation,
            Errno::NOENT => CacheError::NotFound,
            _ => CacheError::IoError,
        })?;

        open_confined_readonly_at(&root_fd, relative_path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let root_meta = std::fs::symlink_metadata(root_dir).map_err(|_| CacheError::IoError)?;
        if root_meta.file_type().is_symlink() {
            return Err(CacheError::PathViolation);
        }
        let mut cursor = root_dir.to_path_buf();
        for segment in relative_path.split('/') {
            cursor.push(segment);
            let meta = std::fs::symlink_metadata(&cursor).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CacheError::NotFound
                } else {
                    CacheError::IoError
                }
            })?;
            if meta.file_type().is_symlink() {
                return Err(CacheError::PathViolation);
            }
        }
        File::open(&cursor).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CacheError::NotFound
            } else {
                CacheError::IoError
            }
        })
    }
}

fn seal_in_arc_memory<R, F>(
    mut reader: R,
    max_bytes: u64,
    verify_fn: F,
) -> Result<VerifiedReadOnlyBlob, CacheError>
where
    R: Read,
    F: FnOnce(u64, &[u8; 32]) -> Result<(), CacheError>,
{
    let mut collected = Vec::new();
    let mut chunk = [0u8; STREAM_CHUNK_BYTES];
    let mut total_len = 0u64;

    loop {
        let read_n = reader.read(&mut chunk).map_err(|_| CacheError::IoError)?;
        if read_n == 0 {
            break;
        }
        let n_u64 = u64::try_from(read_n).map_err(|_| CacheError::IoError)?;
        total_len = total_len.checked_add(n_u64).ok_or(CacheError::IoError)?;
        if total_len > max_bytes {
            return Err(CacheError::BlobTooLarge {
                len: total_len,
                max: max_bytes,
            });
        }
        collected
            .try_reserve(read_n)
            .map_err(|_| CacheError::IoError)?;
        collected.extend_from_slice(&chunk[..read_n]);
    }

    let immutable: Arc<[u8]> = Arc::from(collected);
    let digest = *blake3::hash(&immutable).as_bytes();
    verify_fn(total_len, &digest)?;

    Ok(VerifiedReadOnlyBlob {
        backing: SealedBacking::Memory {
            bytes: immutable,
            digest,
        },
    })
}

/// Copies at most `max_bytes` from `reader` into an anonymous `memfd`, applies
/// all four kernel seals (`WRITE | SHRINK | GROW | SEAL`), computes `BLAKE3`
/// over the sealed RAM bytes, and runs `verify_fn(len, &digest)` before returning.
///
/// Enforces [`SealPolicy::RequireKernelMemfd`] by default on Linux (failing closed
/// if `memfd_create` or kernel sealing fails).
pub fn seal_and_verify_reader<R, F>(
    reader: R,
    max_bytes: u64,
    verify_fn: F,
) -> Result<VerifiedReadOnlyBlob, CacheError>
where
    R: Read,
    F: FnOnce(u64, &[u8; 32]) -> Result<(), CacheError>,
{
    seal_and_verify_reader_with_policy(reader, max_bytes, SealPolicy::RequireKernelMemfd, verify_fn)
}

/// Copies at most `max_bytes` from `reader` under an explicit [`SealPolicy`].
pub fn seal_and_verify_reader_with_policy<R, F>(
    mut reader: R,
    max_bytes: u64,
    policy: SealPolicy,
    verify_fn: F,
) -> Result<VerifiedReadOnlyBlob, CacheError>
where
    R: Read,
    F: FnOnce(u64, &[u8; 32]) -> Result<(), CacheError>,
{
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, SealFlags};
        use rustix::io::Errno;

        match memfd_create(
            c"locksmith-cache-blob",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        ) {
            Ok(memfd) => {
                let mut chunk = [0u8; STREAM_CHUNK_BYTES];
                let mut total_len = 0u64;

                loop {
                    let read_n = reader.read(&mut chunk).map_err(|_| CacheError::IoError)?;
                    if read_n == 0 {
                        break;
                    }
                    let n_u64 = u64::try_from(read_n).map_err(|_| CacheError::IoError)?;
                    total_len = total_len.checked_add(n_u64).ok_or(CacheError::IoError)?;
                    if total_len > max_bytes {
                        return Err(CacheError::BlobTooLarge {
                            len: total_len,
                            max: max_bytes,
                        });
                    }

                    let mut written = 0usize;
                    while written < read_n {
                        match rustix::io::write(&memfd, &chunk[written..read_n]) {
                            Ok(0) => return Err(CacheError::SealFailed),
                            Ok(w) => {
                                written = written.checked_add(w).ok_or(CacheError::SealFailed)?;
                            }
                            Err(Errno::INTR) => {}
                            Err(_) => return Err(CacheError::SealFailed),
                        }
                    }
                }

                // Seal the anonymous RAM descriptor BEFORE hashing/verifying so TOCTOU is impossible.
                let required =
                    SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL;
                fcntl_add_seals(&memfd, required).map_err(|_| CacheError::SealFailed)?;
                let active = fcntl_get_seals(&memfd).map_err(|_| CacheError::SealFailed)?;
                if !active.contains(required) {
                    return Err(CacheError::SealFailed);
                }

                let len_usize = usize::try_from(total_len).map_err(|_| CacheError::SealFailed)?;
                let mut hasher = blake3::Hasher::new();
                let mut read_offset = 0usize;
                while read_offset < len_usize {
                    let rem = (len_usize - read_offset).min(STREAM_CHUNK_BYTES);
                    let pos_u64 = u64::try_from(read_offset).map_err(|_| CacheError::SealFailed)?;
                    match rustix::io::pread(&memfd, &mut chunk[..rem], pos_u64) {
                        Ok(0) => return Err(CacheError::SealFailed),
                        Ok(n) => {
                            hasher.update(&chunk[..n]);
                            read_offset =
                                read_offset.checked_add(n).ok_or(CacheError::SealFailed)?;
                        }
                        Err(Errno::INTR) => {}
                        Err(_) => return Err(CacheError::SealFailed),
                    }
                }

                let digest = *hasher.finalize().as_bytes();
                verify_fn(total_len, &digest)?;

                Ok(VerifiedReadOnlyBlob {
                    backing: SealedBacking::Memfd {
                        fd: memfd,
                        len: len_usize,
                        digest,
                    },
                })
            }
            Err(Errno::NOSYS | Errno::PERM) if policy == SealPolicy::AllowUnsealedFallback => {
                seal_in_arc_memory(reader, max_bytes, verify_fn)
            }
            Err(_) => Err(CacheError::SealFailed),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        seal_in_arc_memory(reader, max_bytes, verify_fn)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn seals_in_ram_and_verifies_blake3_digest() {
        let data = b"verified-in-ram-immutable-payload";
        let expected_hash = *blake3::hash(data).as_bytes();

        let blob = seal_and_verify_reader(Cursor::new(data), 1024, |len, digest| {
            assert_eq!(len, data.len() as u64);
            if digest == &expected_hash {
                Ok(())
            } else {
                Err(CacheError::IntegrityMismatch)
            }
        })
        .unwrap();

        #[cfg(target_os = "linux")]
        assert!(blob.is_kernel_sealed());

        assert_eq!(blob.len(), data.len());
        assert_eq!(blob.content_digest(), &expected_hash);
        assert_eq!(blob.read_to_vec().unwrap(), data);
    }
}
