use super::{AetherIcedShell, Tab};

impl AetherIcedShell {
    pub(super) fn dashboard_search_placeholder(&self) -> &'static str {
        let scope = if self.active_tab == Tab::Home {
            self.dashboard_nav.as_str()
        } else {
            match self.active_tab {
                Tab::StructureMap => "Threat Graph",
                Tab::ADE => "Threat Analysis",
                Tab::Browser => "Browser",
                Tab::YouTube => "YouTube",
                Tab::Symbiont => "Symbiont",
                Tab::SwarmOps => "Swarm Ops",
                Tab::Data => "Files",
                _ => "Overview",
            }
        };
        match scope {
            "Threat Graph" => "Threat Graph: anchor, delta, entropy, node, attractor",
            "Threat Analysis" => "Threat Analysis: risk, residual, convergence, lossless",
            "Browser" => "Browser: domain, URL, keyword oder Frage",
            "YouTube" => "YouTube: Kanal, Video-ID, Thema oder URL",
            "Symbiont" => "Symbiont: profile, razor, snapshot, status",
            "Swarm Ops" => "Swarm: node, quorum, consensus, pack, genesis",
            "Files" => "Files: Dateiname, Typ, Delta, Entropie",
            _ => "Suche: threat, anchor, browser, youtube, symbiont, runtime",
        }
    }

    pub(super) fn dashboard_search_help(&self) -> &'static str {
        let scope = if self.active_tab == Tab::Home {
            self.dashboard_nav.as_str()
        } else {
            ""
        };
        match scope {
            "Threat Graph" => "Hinweis: Suche filtert Begriffe in Threat/Device-Tabellen und Navigator. Beispiele: anchor, delta, node-aether.",
            "Browser" => "Hinweis: Fuer Websuche Schlagwort oder Frage eingeben; fuer direkte Navigation volle URL verwenden.",
            "YouTube" => "Hinweis: URL wie https://www.youtube.com/watch?v=... oder Suchbegriff im Browser-Tab verwenden.",
            "Symbiont" => "Hinweis: Mehrzeilige Eingaben im Symbiont-Tab erzeugen Razor-Listen (eine Zeile = ein Signal).",
            _ => match self.active_tab {
                Tab::Control => "Control: Suche filtert KPIs, Metriken und Status-Labels im Ueberblick-Dashboard.",
                Tab::Chat => "Chat: Nachricht eingeben.",
                Tab::Logs => "Logs: Suche filtert nach Aktion, Kandidaten-ID, Regel-ID oder Zeitstempel.",
                Tab::Settings => "Settings: Suche filtert Konfigurationsoptionen nach Stichwort.",
                Tab::Anchors => "Anchors: Suche filtert nach Ankernamen, UUID oder Vault-Klassifikation.",
                Tab::Data => "Data: Suche filtert nach Dateiname, Dateityp oder Metadaten-Feld.",
                _ => "Hinweis: Suchfeld arbeitet kontextbezogen (Tab + Dashboard-Ansicht).",
            },
        }
    }
}
