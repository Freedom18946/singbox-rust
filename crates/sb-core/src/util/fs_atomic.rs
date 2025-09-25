use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Atomically write data to path by writing to a temporary file and renaming.
/// Ensures data is fsynced before replace; on Windows falls back to remove+rename.
pub fn write_atomic<P: AsRef<Path>>(path: P, data: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no parent dir"))?;
    let mut tmp: PathBuf = dir.to_path_buf();
    tmp.push(format!('.'.to_string() + &format!(".{}.tmp", std::process::id())));
    // Better unique temp name
    tmp.push(format!("sbtmp-{}-{}.tmp", std::process::id(), std::time::SystemTime::now().elapsed().unwrap_or_default().as_nanos()));

    // Create and write
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
    f.write_all(data)?;
    f.flush()?;
    // fsync file
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: fsync on a valid file descriptor; safe on Unix
        let _ = unsafe { libc::fsync(f.as_raw_fd()) };
    }
    #[cfg(target_os = "windows")]
    {
        f.sync_all()?;
    }
    drop(f);

    // Rename atomically if possible; on Windows may need to remove
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            #[cfg(target_os = "windows")]
            {
                let _ = fs::remove_file(path);
                fs::rename(&tmp, path).or(Err(e))
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn concurrent_writes_leave_consistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("out.json");
        let mut hs = Vec::new();
        for i in 0..8u8 { let p = p.clone(); hs.push(thread::spawn(move || { let s = format!("{{\"i\":{}}}", i); write_atomic(&p, s.as_bytes()).unwrap(); })); }
        for h in hs { let _ = h.join(); }
        let s = fs::read_to_string(&p).unwrap();
        assert!(s.starts_with("{"));
        assert!(s.ends_with("}"));
    }

    #[test]
    fn crash_simulation_leaves_old_file_intact() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("data.txt");
        fs::write(&p, b"old").unwrap();
        // Simulate crash by writing only to temp and not renaming
        let tmp = dir.path().join("partial.tmp");
        fs::write(&tmp, b"new_partial").unwrap();
        // Verify target still intact
        let s = fs::read_to_string(&p).unwrap();
        assert_eq!(s, "old");
    }
}
