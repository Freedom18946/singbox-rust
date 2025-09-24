pub mod process;
pub mod tun;

#[cfg(target_os = "linux")]
pub mod os {
    pub const NAME: &str = "linux";
}
#[cfg(target_os = "macos")]
pub mod os {
    pub const NAME: &str = "macos";
}
#[cfg(target_os = "windows")]
pub mod os {
    pub const NAME: &str = "windows";
}
