use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterEntry {
    pub id: u64,
    pub owner_username: String,
    pub file_name: String,
    pub full_path: String,
    pub source_kind: String,
    pub original_size: u64,
    pub delta_size: u64,
    pub compression_gain_percent: f32,
    pub anchor_summary: String,
    pub process_summary: String,
    pub preview_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChatMessage {
    pub author: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivateThread {
    pub owner_username: String,
    pub partner_name: String,
    pub messages: Vec<ChatMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupRoom {
    pub owner_username: String,
    pub name: String,
    pub messages: Vec<ChatMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredState {
    next_entry_id: u64,
    register_entries: Vec<RegisterEntry>,
    private_threads: Vec<PrivateThread>,
    group_rooms: Vec<GroupRoom>,
}

impl Default for StoredState {
    fn default() -> Self {
        Self {
            next_entry_id: 1,
            register_entries: Vec::new(),
            private_threads: Vec::new(),
            group_rooms: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
    state: StoredState,
}

impl StateStore {
    pub fn load_default() -> Self {
        let path = PathBuf::from("data").join("rust_shell").join("state.json");
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Self {
        let state = load_state(&path).unwrap_or_default();
        Self { path, state }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("State-Verzeichnis konnte nicht erstellt werden: {err}"))?;
        }
        let serialized = serde_json::to_string_pretty(&self.state)
            .map_err(|err| format!("State konnte nicht serialisiert werden: {err}"))?;
        fs::write(&self.path, serialized)
            .map_err(|err| format!("State konnte nicht gespeichert werden: {err}"))?;
        Ok(())
    }

    pub fn entries_for(&self, username: &str) -> Vec<RegisterEntry> {
        let mut entries: Vec<RegisterEntry> = self
            .state
            .register_entries
            .iter()
            .filter(|entry| entry.owner_username == username)
            .cloned()
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.id));
        entries
    }

    pub fn add_register_entry(&mut self, mut entry: RegisterEntry) -> Result<u64, String> {
        entry.id = self.state.next_entry_id;
        self.state.next_entry_id += 1;
        self.state.register_entries.push(entry.clone());
        self.save()?;
        Ok(entry.id)
    }

    pub fn private_thread(&mut self, username: &str, partner: &str) -> &mut PrivateThread {
        if let Some(index) =
            self.state.private_threads.iter().position(|thread| {
                thread.owner_username == username && thread.partner_name == partner
            })
        {
            return &mut self.state.private_threads[index];
        }
        self.state.private_threads.push(PrivateThread {
            owner_username: username.to_owned(),
            partner_name: partner.to_owned(),
            messages: Vec::new(),
        });
        let index = self.state.private_threads.len().saturating_sub(1);
        &mut self.state.private_threads[index]
    }

    pub fn group_room(&mut self, username: &str, group_name: &str) -> &mut GroupRoom {
        if let Some(index) = self
            .state
            .group_rooms
            .iter()
            .position(|room| room.owner_username == username && room.name == group_name)
        {
            return &mut self.state.group_rooms[index];
        }
        self.state.group_rooms.push(GroupRoom {
            owner_username: username.to_owned(),
            name: group_name.to_owned(),
            messages: Vec::new(),
        });
        let index = self.state.group_rooms.len().saturating_sub(1);
        &mut self.state.group_rooms[index]
    }

    pub fn private_threads_for(&self, username: &str) -> Vec<PrivateThread> {
        self.state
            .private_threads
            .iter()
            .filter(|thread| thread.owner_username == username)
            .cloned()
            .collect()
    }

    pub fn group_rooms_for(&self, username: &str) -> Vec<GroupRoom> {
        self.state
            .group_rooms
            .iter()
            .filter(|room| room.owner_username == username)
            .cloned()
            .collect()
    }
}

fn load_state(path: &Path) -> Option<StoredState> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<StoredState>(&raw).ok()
}
