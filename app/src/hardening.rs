#[cfg(target_os = "linux")]
pub fn apply() {
    use nix::sys::prctl::{set_dumpable, set_no_new_privs};
    use nix::sys::resource::{setrlimit, Resource, Rlim};

    if std::env::var("SB_HARDEN").ok().as_deref() != Some("1") {
        return;
    }

    let limit = Rlim::from_raw(1_048_576);
    let _ = setrlimit(Resource::RLIMIT_NOFILE, limit, limit);
    let _ = set_dumpable(false);
    let _ = set_no_new_privs();
}

#[cfg(not(target_os = "linux"))]
pub fn apply() {}
