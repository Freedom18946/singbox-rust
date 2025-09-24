#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]|{
  if let Ok(s)=std::str::from_utf8(data){
    let _=sb_core::config::try_parse_str(s); // 需在 sb-core 暴露 try_parse_str
  }
});