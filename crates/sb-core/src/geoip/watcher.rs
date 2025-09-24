#![cfg(feature="geoip_hot")]
use std::{sync::Arc, time::Duration, path::PathBuf};
use notify::{RecommendedWatcher, Watcher, EventKind};
use crate::geoip::multi::MultiReader;
pub fn spawn_hot_reload(mmdb:PathBuf, m:Arc<MultiReader>){
  let (tx,rx)=std::sync::mpsc::channel();
  let mut w:RecommendedWatcher=Watcher::new(tx, Duration::from_millis(200)).expect("watcher");
  w.watch(&mmdb, notify::RecursiveMode::NonRecursive).ok();
  std::thread::spawn(move||{
    while let Ok(ev)=rx.recv(){
      if matches!(ev.kind, EventKind::Modify(_)|EventKind::Create(_)) {
        let _=m.reload_from(&mmdb);
      }
    }
  });
}