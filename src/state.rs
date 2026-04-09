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
    #[serde(default)]
    pub plain_note: String,
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
    #[serde(default)]
    pub id: String,
    pub owner_username: String,
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub messages: Vec<ChatMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockedUser {
    pub owner_username: String,
    pub blocked_username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredState {
    next_entry_id: u64,
    register_entries: Vec<RegisterEntry>,
    private_threads: Vec<PrivateThread>,
    group_rooms: Vec<GroupRoom>,
    #[serde(default)]
    blocked_users: Vec<BlockedUser>,
}

impl Default for StoredState {
    fn default() -> Self {
        Self {
            next_entry_id: 1,
            register_entries: Vec::new(),
            private_threads: Vec::new(),
            group_rooms: Vec::new(),
            blocked_users: Vec::new(),
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
        let path = crate::data_path("rust_shell/state.json");
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Self {
        let mut state = load_state(&path).unwrap_or_default();
        normalize_state(&mut state);
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

    pub fn create_group_room(&mut self, username: &str, group_name: &str) -> Result<String, String> {
        let trimmed = group_name.trim();
        if trimmed.is_empty() {
            return Err("Gruppenname darf nicht leer sein.".to_owned());
        }
        let room_id = group_room_id(username, trimmed);
        if self.group_room_index(&room_id).is_some() {
            return Err("Gruppe existiert bereits.".to_owned());
        }
        self.state.group_rooms.push(GroupRoom {
            id: room_id.clone(),
            owner_username: username.to_owned(),
            name: trimmed.to_owned(),
            members: vec![username.to_owned()],
            messages: Vec::new(),
        });
        self.save()?;
        Ok(room_id)
    }

    pub fn private_threads_for(&self, username: &str) -> Vec<PrivateThread> {
        let mut threads = self
            .state
            .private_threads
            .iter()
            .filter(|thread| thread.owner_username == username)
            .cloned()
            .collect::<Vec<_>>();
        threads.sort_by(|left, right| left.partner_name.cmp(&right.partner_name));
        threads
    }

    pub fn group_rooms_for(&self, username: &str) -> Vec<GroupRoom> {
        let mut rooms = self
            .state
            .group_rooms
            .iter()
            .filter(|room| {
                room.owner_username == username
                    || room.members.iter().any(|member| member == username)
            })
            .cloned()
            .collect::<Vec<_>>();
        rooms.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.owner_username.cmp(&right.owner_username))
        });
        rooms
    }

    pub fn blocked_users_for(&self, username: &str) -> Vec<String> {
        let mut blocked = self
            .state
            .blocked_users
            .iter()
            .filter(|entry| entry.owner_username == username)
            .map(|entry| entry.blocked_username.clone())
            .collect::<Vec<_>>();
        blocked.sort();
        blocked.dedup();
        blocked
    }

    pub fn is_blocked(&self, username: &str, target: &str) -> bool {
        self.state.blocked_users.iter().any(|entry| {
            entry.owner_username == username && entry.blocked_username == target
        })
    }

    pub fn is_blocked_between(&self, left: &str, right: &str) -> bool {
        self.is_blocked(left, right) || self.is_blocked(right, left)
    }

    pub fn block_user(&mut self, username: &str, target: &str) -> Result<(), String> {
        let target = target.trim();
        if target.is_empty() {
            return Err("Blockieren ohne Ziel ist nicht moeglich.".to_owned());
        }
        if username == target {
            return Err("Eigenes Konto kann nicht blockiert werden.".to_owned());
        }
        if !self.is_blocked(username, target) {
            self.state.blocked_users.push(BlockedUser {
                owner_username: username.to_owned(),
                blocked_username: target.to_owned(),
            });
        }
        self.save()
    }

    pub fn unblock_user(&mut self, username: &str, target: &str) -> Result<(), String> {
        self.state.blocked_users.retain(|entry| {
            !(entry.owner_username == username && entry.blocked_username == target)
        });
        self.save()
    }

    pub fn add_private_message(
        &mut self,
        owner_username: &str,
        partner_name: &str,
        author: &str,
        body: &str,
    ) -> Result<(), String> {
        let thread = self.private_thread(owner_username, partner_name);
        thread.messages.push(ChatMessage {
            author: author.to_owned(),
            body: body.to_owned(),
        });
        self.save()
    }

    pub fn add_group_message(
        &mut self,
        room_id: &str,
        author: &str,
        body: &str,
    ) -> Result<(), String> {
        let Some(index) = self.group_room_index(room_id) else {
            return Err("Gruppe nicht gefunden.".to_owned());
        };
        let room = &mut self.state.group_rooms[index];
        if room.owner_username != author && !room.members.iter().any(|member| member == author) {
            return Err("Nur Mitglieder duerfen in diese Gruppe schreiben.".to_owned());
        }
        room.messages.push(ChatMessage {
            author: author.to_owned(),
            body: body.to_owned(),
        });
        self.save()
    }

    pub fn add_group_member(
        &mut self,
        actor_username: &str,
        room_id: &str,
        member_username: &str,
    ) -> Result<(), String> {
        let member_username = member_username.trim();
        if member_username.is_empty() {
            return Err("Mitgliedsname darf nicht leer sein.".to_owned());
        }
        let Some(index) = self.group_room_index(room_id) else {
            return Err("Gruppe nicht gefunden.".to_owned());
        };
        let room = &mut self.state.group_rooms[index];
        if room.owner_username != actor_username {
            return Err("Nur der Ersteller darf Mitglieder hinzufuegen.".to_owned());
        }
        if room.owner_username == member_username || room.members.iter().any(|member| member == member_username) {
            return Err("Mitglied ist bereits in der Gruppe.".to_owned());
        }
        room.members.push(member_username.to_owned());
        dedupe_members(room);
        self.save()
    }

    pub fn remove_group_member(
        &mut self,
        actor_username: &str,
        room_id: &str,
        member_username: &str,
    ) -> Result<(), String> {
        let Some(index) = self.group_room_index(room_id) else {
            return Err("Gruppe nicht gefunden.".to_owned());
        };
        let room = &mut self.state.group_rooms[index];
        if room.owner_username != actor_username {
            return Err("Nur der Ersteller darf Mitglieder entfernen.".to_owned());
        }
        if member_username == room.owner_username {
            return Err("Der Ersteller kann sich nicht ueber Entfernen selbst loeschen. Nutze Verlassen.".to_owned());
        }
        let before = room.members.len();
        room.members.retain(|member| member != member_username);
        if room.members.len() == before {
            return Err("Mitglied war nicht in der Gruppe.".to_owned());
        }
        self.save()
    }

    pub fn leave_group(&mut self, username: &str, room_id: &str) -> Result<(), String> {
        let Some(index) = self.group_room_index(room_id) else {
            return Err("Gruppe nicht gefunden.".to_owned());
        };
        let room = &mut self.state.group_rooms[index];
        if room.owner_username != username && !room.members.iter().any(|member| member == username) {
            return Err("Nur Mitglieder koennen die Gruppe verlassen.".to_owned());
        }
        if room.owner_username == username {
            let remaining = room
                .members
                .iter()
                .filter(|member| member.as_str() != username)
                .cloned()
                .collect::<Vec<_>>();
            if let Some(next_owner) = remaining.first().cloned() {
                room.owner_username = next_owner;
                room.members = remaining;
            } else {
                self.state.group_rooms.remove(index);
                return self.save();
            }
        } else {
            room.members.retain(|member| member != username);
        }
        self.save()
    }

    pub fn group_room_by_id(&self, room_id: &str) -> Option<GroupRoom> {
        self.state
            .group_rooms
            .iter()
            .find(|room| group_room_id_for_room(room) == room_id)
            .cloned()
    }

    fn group_room_index(&self, room_id: &str) -> Option<usize> {
        self.state
            .group_rooms
            .iter()
            .position(|room| group_room_id_for_room(room) == room_id)
    }
}

fn load_state(path: &Path) -> Option<StoredState> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<StoredState>(&raw).ok()
}

fn normalize_state(state: &mut StoredState) {
    for room in &mut state.group_rooms {
        if room.id.trim().is_empty() {
            room.id = group_room_id(&room.owner_username, &room.name);
        }
        dedupe_members(room);
    }
    state.blocked_users.sort_by(|left, right| {
        left.owner_username
            .cmp(&right.owner_username)
            .then(left.blocked_username.cmp(&right.blocked_username))
    });
    state.blocked_users.dedup_by(|left, right| {
        left.owner_username == right.owner_username
            && left.blocked_username == right.blocked_username
    });
}

fn dedupe_members(room: &mut GroupRoom) {
    let mut ordered = Vec::new();
    if !room.owner_username.trim().is_empty() {
        ordered.push(room.owner_username.clone());
    }
    for member in room.members.iter().cloned() {
        if member != room.owner_username && !ordered.iter().any(|existing| existing == &member) {
            ordered.push(member);
        }
    }
    room.members = ordered;
}

fn canonical_group_fragment(value: &str) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join("-");
    let mut normalized = compact
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while normalized.contains("--") {
        normalized = normalized.replace("--", "-");
    }
    normalized.trim_matches('-').to_owned()
}

fn group_room_id(owner_username: &str, group_name: &str) -> String {
    format!(
        "{}::{}",
        canonical_group_fragment(owner_username),
        canonical_group_fragment(group_name)
    )
}

fn group_room_id_for_room(room: &GroupRoom) -> String {
    if room.id.trim().is_empty() {
        group_room_id(&room.owner_username, &room.name)
    } else {
        room.id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("aether-state-{label}-{nanos}.json"))
    }

    #[test]
    fn blocklist_is_checked_bidirectionally() {
        let path = temp_state_path("block");
        let mut store = StateStore::load_from(path.clone());
        store.block_user("alice", "bob").expect("block succeeds");
        assert!(store.is_blocked("alice", "bob"));
        assert!(store.is_blocked_between("alice", "bob"));
        assert!(store.is_blocked_between("bob", "alice"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn group_owner_can_manage_members_and_leave_reassigns_room() {
        let path = temp_state_path("group");
        let mut store = StateStore::load_from(path.clone());
        let room_id = store
            .create_group_room("alice", "Forschung")
            .expect("group created");
        store
            .add_group_member("alice", &room_id, "bob")
            .expect("add bob");
        store
            .add_group_member("alice", &room_id, "carol")
            .expect("add carol");
        store
            .remove_group_member("alice", &room_id, "carol")
            .expect("remove carol");
        store
            .add_group_message(&room_id, "bob", "Hallo Gruppe")
            .expect("member can write");

        let room = store.group_room_by_id(&room_id).expect("room exists");
        assert_eq!(room.members, vec!["alice", "bob"]);
        assert_eq!(room.messages.len(), 1);

        store.leave_group("alice", &room_id).expect("owner can leave");
        let reassigned = store.group_room_by_id(&room_id).expect("room reassigned");
        assert_eq!(reassigned.owner_username, "bob");
        assert_eq!(reassigned.members, vec!["bob"]);
        let _ = fs::remove_file(path);
    }
}
