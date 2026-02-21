use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowBookmark {
    pub flow_label: String,
    pub flow_key: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CaseFile {
    pub pcap_path: String,
    pub bookmarks: Vec<FlowBookmark>,
}

pub fn case_dir_for_pcap(pcap_path: &Path) -> PathBuf {
    let base = pcap_path.parent().unwrap_or_else(|| Path::new("."));
    base.join(".babyshark")
}

pub fn case_path_for_pcap(pcap_path: &Path) -> PathBuf {
    case_dir_for_pcap(pcap_path).join("case.json")
}

impl CaseFile {
    pub fn load_or_new(pcap_path: &Path) -> Result<CaseFile> {
        let path = case_path_for_pcap(pcap_path);
        if !path.exists() {
            return Ok(CaseFile {
                pcap_path: pcap_path.to_string_lossy().to_string(),
                bookmarks: vec![],
            });
        }
        let s = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let mut cf: CaseFile = serde_json::from_str(&s).with_context(|| "parse case.json")?;
        // keep in sync
        cf.pcap_path = pcap_path.to_string_lossy().to_string();
        Ok(cf)
    }

    pub fn save(&self, pcap_path: &Path) -> Result<()> {
        let dir = case_dir_for_pcap(pcap_path);
        fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let path = case_path_for_pcap(pcap_path);
        let s = serde_json::to_string_pretty(self).with_context(|| "serialize case.json")?;
        fs::write(&path, s).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    pub fn upsert_bookmark(&mut self, flow_key: &str, flow_label: &str, note: &str) {
        if let Some(b) = self.bookmarks.iter_mut().find(|b| b.flow_key == flow_key) {
            b.flow_label = flow_label.to_string();
            b.note = note.to_string();
            return;
        }
        self.bookmarks.push(FlowBookmark {
            flow_label: flow_label.to_string(),
            flow_key: flow_key.to_string(),
            note: note.to_string(),
        });
    }
}
