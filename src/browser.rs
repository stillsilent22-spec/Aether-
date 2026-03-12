use reqwest::header::{ACCEPT_LANGUAGE, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::runtime::Builder;

const HATE_PATTERN_TERMS: &[&str] = &[
    "hate",
    "hass",
    "vermin",
    "parasite",
    "parasiten",
    "subhuman",
    "abschaum",
    "vernichten",
    "ausrotten",
];
const SCAM_PATTERN_TERMS: &[&str] = &[
    "wallet",
    "seed phrase",
    "urgent",
    "dringend",
    "limited offer",
    "verdienen",
    "bitcoin",
    "crypto",
    "konto",
    "password",
    "passwort",
    "gift card",
];
const FAKE_PATTERN_TERMS: &[&str] = &[
    "breaking",
    "schock",
    "exclusive",
    "unglaublich",
    "leaked",
    "geheime wahrheit",
    "wake up",
    "die medien",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProbePolicy {
    pub scope: String,
    pub consent_required: bool,
    pub allow_probe: bool,
    pub max_probe_bytes: usize,
    pub warn_threshold: f32,
    pub block_threshold: f32,
    pub hash_only_outbound: bool,
    pub fail_closed: bool,
}

impl Default for BrowserProbePolicy {
    fn default() -> Self {
        Self {
            scope: "prompt".to_owned(),
            consent_required: true,
            allow_probe: true,
            max_probe_bytes: 524_288,
            warn_threshold: 0.40,
            block_threshold: 0.72,
            hash_only_outbound: true,
            fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserProbeResult {
    pub ok: bool,
    pub url: String,
    pub final_url: String,
    pub title: String,
    pub summary: String,
    pub text_sample: String,
    pub content_type: String,
    pub category: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub content_length: usize,
    pub secure: bool,
    pub entropy: f32,
    pub header_entropy: f32,
    pub script_count: usize,
    pub style_count: usize,
    pub inline_base64: usize,
    pub eval_hits: usize,
    pub external_resources: usize,
    pub obfuscation_score: f32,
    pub ai_generation_score: f32,
    pub hate_risk_score: f32,
    pub fake_risk_score: f32,
    pub scam_risk_score: f32,
    pub risk_score: f32,
    pub risk_label: String,
    pub risk_reasons: Vec<String>,
    pub frontend_summary: String,
    pub backend_summary: String,
    pub missing_data: Vec<String>,
    pub open_recommended: bool,
    pub frontend_symmetry: f32,
    pub frontend_entropy: f32,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserSearchContext {
    pub ok: bool,
    pub provider: String,
    pub query: String,
    pub url: String,
    pub summary: String,
    pub search_url: String,
    pub error: String,
}

#[derive(Debug, Clone)]
struct DownloadPayload {
    final_url: String,
    status_code: u16,
    headers: HashMap<String, String>,
    content_type: String,
    content_length: usize,
    raw_bytes: Vec<u8>,
    secure: bool,
}

pub struct BrowserInspector;

impl BrowserInspector {
    pub fn normalize_url(url: &str) -> String {
        let candidate = url.trim();
        if candidate.is_empty() {
            return "https://example.org".to_owned();
        }
        if candidate.starts_with("http://") || candidate.starts_with("https://") {
            return candidate.to_owned();
        }
        format!("https://{candidate}")
    }

    pub fn build_search_url(query: &str, provider: &str) -> String {
        let cleaned = if query.trim().is_empty() {
            "file format structure"
        } else {
            query.trim()
        };
        let encoded = encode_query(cleaned);
        match provider.trim().to_ascii_lowercase().as_str() {
            "bing" => format!("https://www.bing.com/search?q={encoded}"),
            "google" => format!("https://www.google.com/search?q={encoded}"),
            _ => format!("https://duckduckgo.com/?q={encoded}"),
        }
    }

    pub fn build_search_fetch_url(
        query: &str,
        provider: &str,
        searx_base_url: &str,
    ) -> Result<String, String> {
        let cleaned = if query.trim().is_empty() {
            "file format structure"
        } else {
            query.trim()
        };
        let encoded = encode_query(cleaned);
        match provider.trim().to_ascii_lowercase().as_str() {
            "searxng" => {
                let base = searx_base_url.trim().trim_end_matches('/');
                if base.is_empty() {
                    return Err("SearxNG-Provider erfordert eine Basis-URL.".to_owned());
                }
                Ok(format!("{base}/search?q={encoded}&format=html"))
            }
            _ => Ok(format!("https://duckduckgo.com/html/?q={encoded}")),
        }
    }

    pub fn fetch_search_context(
        query: &str,
        provider: &str,
        timeout_secs: f32,
        searx_base_url: &str,
    ) -> BrowserSearchContext {
        let cleaned = query.split_whitespace().collect::<Vec<_>>().join(" ");
        if cleaned.trim().is_empty() {
            return BrowserSearchContext {
                ok: false,
                provider: provider.to_owned(),
                query: String::new(),
                url: String::new(),
                summary: String::new(),
                search_url: String::new(),
                error: "empty_query".to_owned(),
            };
        }
        let fetch_url = match Self::build_search_fetch_url(&cleaned, provider, searx_base_url) {
            Ok(value) => value,
            Err(err) => {
                return BrowserSearchContext {
                    ok: false,
                    provider: provider.to_owned(),
                    query: cleaned.clone(),
                    url: String::new(),
                    summary: String::new(),
                    search_url: Self::build_search_url(&cleaned, provider),
                    error: err,
                };
            }
        };
        match Self::download_text(&fetch_url, timeout_secs.max(1.0)) {
            Ok(raw_html) => {
                let summary = Self::strip_html_text(&raw_html, 1_200);
                BrowserSearchContext {
                    ok: !summary.is_empty(),
                    provider: provider.to_owned(),
                    query: cleaned.clone(),
                    url: fetch_url,
                    summary,
                    search_url: Self::build_search_url(&cleaned, provider),
                    error: String::new(),
                }
            }
            Err(err) => BrowserSearchContext {
                ok: false,
                provider: provider.to_owned(),
                query: cleaned.clone(),
                url: String::new(),
                summary: String::new(),
                search_url: Self::build_search_url(&cleaned, provider),
                error: err,
            },
        }
    }

    pub fn inspect_url(url: &str, policy: &BrowserProbePolicy) -> BrowserProbeResult {
        if !policy.allow_probe {
            return BrowserProbeResult {
                ok: false,
                url: Self::normalize_url(url),
                final_url: Self::normalize_url(url),
                risk_label: "CRITICAL".to_owned(),
                risk_score: 1.0,
                risk_reasons: vec!["Browser-Probe bleibt fail-closed deaktiviert.".to_owned()],
                open_recommended: false,
                error: "probe_disabled".to_owned(),
                ..BrowserProbeResult::default()
            };
        }
        let normalized_url = Self::normalize_url(url);
        match Self::download_payload(&normalized_url, 6.0, policy.max_probe_bytes.max(1_024)) {
            Ok(download) => Self::analyze_download(&normalized_url, download, policy),
            Err(err) => BrowserProbeResult {
                ok: false,
                url: normalized_url.clone(),
                final_url: normalized_url,
                risk_label: "CRITICAL".to_owned(),
                risk_score: 1.0,
                risk_reasons: vec![format!("Download fehlgeschlagen: {err}")],
                open_recommended: false,
                error: err,
                ..BrowserProbeResult::default()
            },
        }
    }

    pub fn strip_html_text(raw_html: &str, limit_chars: usize) -> String {
        let cleaned = collapse_whitespace(&strip_markup(&remove_block(
            &remove_block(raw_html, "<script", "</script>"),
            "<style",
            "</style>",
        )));
        if cleaned.len() <= limit_chars.max(80) {
            cleaned
        } else {
            trimmed_at_boundary(&cleaned, limit_chars.max(80))
        }
    }

    fn analyze_download(
        url: &str,
        download: DownloadPayload,
        policy: &BrowserProbePolicy,
    ) -> BrowserProbeResult {
        let category = categorize_content_type(&download.content_type, &download.final_url);
        let entropy = byte_entropy(&download.raw_bytes);
        let header_blob = download
            .headers
            .iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let header_entropy = byte_entropy(header_blob.as_bytes());
        let mut text_sample = String::new();
        let mut summary = String::new();
        let mut title = host_label(&download.final_url);
        let mut script_count = 0usize;
        let mut style_count = 0usize;
        let mut inline_base64 = 0usize;
        let mut eval_hits = 0usize;
        let mut external_resources = 0usize;
        let mut suspicious_long_lines = 0usize;
        let mut frontend_symmetry = 0.0f32;
        let mut frontend_entropy = 0.0f32;
        let mut preview_summary = "keine Miniatur".to_owned();
        let mut missing_data = Vec::new();
        let mut risk_reasons = Vec::new();

        if category == "html" {
            let html = String::from_utf8_lossy(&download.raw_bytes).to_string();
            text_sample = Self::strip_html_text(&html, 2_000);
            summary = Self::strip_html_text(&html, 720);
            if let Some(extracted_title) = extract_tag_text(&html, "title") {
                if !extracted_title.is_empty() {
                    title = extracted_title;
                }
            }
            let lowered = html.to_ascii_lowercase();
            script_count = count_occurrences(&lowered, "<script");
            style_count = count_occurrences(&lowered, "<style");
            inline_base64 =
                count_occurrences(&lowered, "data:") + count_occurrences(&lowered, ";base64,");
            eval_hits = count_occurrences(&lowered, "eval(")
                + count_occurrences(&lowered, "atob(")
                + count_occurrences(&lowered, "fromcharcode(")
                + count_occurrences(&lowered, "document.write(")
                + count_occurrences(&lowered, "unescape(");
            external_resources = count_occurrences(&lowered, "src=\"http")
                + count_occurrences(&lowered, "src='http")
                + count_occurrences(&lowered, "href=\"http")
                + count_occurrences(&lowered, "href='http");
            suspicious_long_lines = html.lines().filter(|line| line.trim().len() > 320).count();
            let profile = layout_profile(&text_sample);
            frontend_symmetry = profile.0;
            frontend_entropy = profile.1;
            preview_summary = "Layout-Heatmap aus HTML/Textdichte".to_owned();
        } else if category == "text" {
            let text = String::from_utf8_lossy(&download.raw_bytes).to_string();
            text_sample = text.clone();
            summary = trimmed_at_boundary(&collapse_whitespace(&text), 720);
            let profile = layout_profile(&text);
            frontend_symmetry = profile.0;
            frontend_entropy = profile.1;
            preview_summary = "Textlayout".to_owned();
        } else {
            if category == "video" {
                missing_data.push(
                    "Temporale Frame-Drift ohne lokalen Decoder nur stichprobenartig bewertbar"
                        .to_owned(),
                );
            }
            if category == "audio" {
                missing_data.push(
                    "Audiofront ohne lokalen Decoder nur ueber Header und Bytes bewertet"
                        .to_owned(),
                );
            }
            frontend_symmetry = (1.0 - ((entropy - 4.2).abs() / 4.2)).clamp(0.0, 1.0);
            frontend_entropy = (entropy / 8.0).clamp(0.0, 1.0) * 4.0;
            preview_summary = "Entropie-Miniatur aus Bytestrom".to_owned();
        }

        let lowered_text = format!("{title} {summary} {text_sample}").to_ascii_lowercase();
        let hate_hits = count_terms(&lowered_text, HATE_PATTERN_TERMS);
        let scam_hits = count_terms(&lowered_text, SCAM_PATTERN_TERMS);
        let fake_hits = count_terms(&lowered_text, FAKE_PATTERN_TERMS);

        let obfuscation_score = ((0.22 * (eval_hits as f32 / 4.0).min(1.0))
            + (0.18 * (inline_base64 as f32 / 3.0).min(1.0))
            + (0.16 * (suspicious_long_lines as f32 / 6.0).min(1.0))
            + (0.14 * ((entropy - 6.4).max(0.0) / 1.6).min(1.0))
            + (0.10 * (script_count as f32 / 12.0).min(1.0)))
        .clamp(0.0, 1.0);

        let ai_generation_score = ((0.22 * (frontend_entropy / 4.0).min(1.0))
            + (0.18 * (frontend_symmetry - 0.82).max(0.0))
            + (0.14 * ((entropy - 5.8).max(0.0) / 2.0).min(1.0)))
        .clamp(0.0, 1.0);
        let hate_score = ((0.55 * (hate_hits as f32 / 2.0).min(1.0))
            + (0.18 * (fake_hits as f32 / 3.0).min(1.0)))
        .clamp(0.0, 1.0);
        let fake_score = ((0.28 * (fake_hits as f32 / 3.0).min(1.0))
            + (0.18 * ((header_entropy - 4.2).max(0.0) / 2.0).min(1.0))
            + (0.16 * ((entropy - 5.9).max(0.0) / 1.6).min(1.0))
            + (0.12 * (external_resources as f32 / 12.0).min(1.0)))
        .clamp(0.0, 1.0);
        let scam_score = ((0.42 * (scam_hits as f32 / 3.0).min(1.0))
            + (0.28 * obfuscation_score)
            + (0.10 * (eval_hits as f32 / 2.0).min(1.0)))
        .clamp(0.0, 1.0);
        let mut risk_score = ai_generation_score
            .max(hate_score)
            .max(fake_score)
            .max(scam_score)
            .max(obfuscation_score * 0.92);

        if scam_score >= 0.66 || obfuscation_score >= 0.66 {
            risk_reasons.push("Obfuskation oder Script-Verschleierung erkannt".to_owned());
        }
        if hate_score >= 0.52 {
            risk_reasons
                .push("Asymmetrische Sprachmuster mit Hate-Speech-Potenzial erkannt".to_owned());
        }
        if fake_score >= 0.50 {
            risk_reasons.push(
                "Inkonsistente oder sensationsgetriebene Struktur erhoeht Fakenews-Risiko"
                    .to_owned(),
            );
        }
        if ai_generation_score >= 0.46 {
            risk_reasons.push(
                "Frontend-Signale wirken stark synthetisch oder uebermaessig glatt".to_owned(),
            );
        }
        if risk_reasons.is_empty() {
            risk_reasons.push(
                "Keine dominante Anomalie erkannt; Struktur bleibt vorlaeufig konsistent"
                    .to_owned(),
            );
        }

        let mut risk_label = if risk_score >= policy.block_threshold {
            "CRITICAL"
        } else if risk_score >= policy.warn_threshold {
            "SUSPICIOUS"
        } else {
            "CLEAN"
        }
        .to_owned();

        if !download.secure {
            risk_reasons.push("Transport nicht ueber HTTPS gesichert".to_owned());
            risk_score = risk_score.max(0.38);
            if risk_label == "CLEAN" {
                risk_label = "SUSPICIOUS".to_owned();
            }
        }

        let headers = download
            .headers
            .into_iter()
            .filter(|(key, _)| {
                matches!(
                    key.as_str(),
                    "content-type"
                        | "content-length"
                        | "server"
                        | "cache-control"
                        | "content-security-policy"
                        | "x-frame-options"
                )
            })
            .collect::<HashMap<_, _>>();
        let backend_summary = format!(
            "Headers {} | MIME {} | Scripts {} | Styles {} | Obfuskation {:.2}",
            headers.len(),
            if download.content_type.is_empty() {
                "--"
            } else {
                &download.content_type
            },
            script_count,
            style_count,
            obfuscation_score
        );
        let frontend_summary = format!(
            "{} | Frontend-Entropie {:.2} | Symmetrie {:.0}%",
            preview_summary,
            frontend_entropy,
            frontend_symmetry * 100.0
        );

        BrowserProbeResult {
            ok: true,
            url: url.to_owned(),
            final_url: download.final_url,
            title,
            summary: if summary.is_empty() {
                trimmed_at_boundary(&text_sample, 720)
            } else {
                summary
            },
            text_sample,
            content_type: download.content_type,
            category,
            status_code: download.status_code,
            headers,
            content_length: download.content_length,
            secure: download.secure,
            entropy,
            header_entropy,
            script_count,
            style_count,
            inline_base64,
            eval_hits,
            external_resources,
            obfuscation_score,
            ai_generation_score,
            hate_risk_score: hate_score,
            fake_risk_score: fake_score,
            scam_risk_score: scam_score,
            risk_score: risk_score.clamp(0.0, 1.0),
            risk_label: risk_label.clone(),
            risk_reasons: dedupe(risk_reasons),
            frontend_summary,
            backend_summary,
            missing_data,
            open_recommended: risk_label == "CLEAN",
            frontend_symmetry,
            frontend_entropy,
            error: String::new(),
        }
    }

    fn download_payload(
        url: &str,
        timeout_secs: f32,
        max_bytes: usize,
    ) -> Result<DownloadPayload, String> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| err.to_string())?;
        runtime.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs_f32(timeout_secs.max(1.0)))
                .build()
                .map_err(|err| err.to_string())?;
            let response = client
                .get(url)
                .header(USER_AGENT, "AetherBrowser/1.0 (+local probe)")
                .header(ACCEPT_LANGUAGE, "de-DE,de;q=0.8,en;q=0.6")
                .send()
                .await
                .map_err(|err| err.to_string())?;
            let status_code = response.status().as_u16();
            let final_url = response.url().to_string();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(key, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|decoded| (key.as_str().to_ascii_lowercase(), decoded.to_owned()))
                })
                .collect::<HashMap<_, _>>();
            let content_type = headers
                .get("content-type")
                .map(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase()
                })
                .unwrap_or_default();
            let mut raw_bytes = Vec::new();
            let mut response = response;
            while let Some(chunk) = response.chunk().await.map_err(|err| err.to_string())? {
                let remaining = max_bytes.saturating_sub(raw_bytes.len());
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(chunk.len());
                raw_bytes.extend_from_slice(&chunk[..take]);
                if raw_bytes.len() >= max_bytes {
                    break;
                }
            }
            Ok(DownloadPayload {
                final_url: final_url.clone(),
                status_code,
                headers,
                content_type,
                content_length: raw_bytes.len(),
                raw_bytes,
                secure: final_url.starts_with("https://"),
            })
        })
    }

    fn download_text(url: &str, timeout_secs: f32) -> Result<String, String> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| err.to_string())?;
        runtime.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs_f32(timeout_secs.max(1.0)))
                .build()
                .map_err(|err| err.to_string())?;
            client
                .get(url)
                .header(USER_AGENT, "AetherBrowser/1.0 (+local companion)")
                .header(ACCEPT_LANGUAGE, "de-DE,de;q=0.8,en;q=0.6")
                .send()
                .await
                .map_err(|err| err.to_string())?
                .text()
                .await
                .map_err(|err| err.to_string())
        })
    }
}

fn encode_query(text: &str) -> String {
    let mut output = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn remove_block(source: &str, start_tag: &str, end_tag: &str) -> String {
    let lower = source.to_ascii_lowercase();
    let start = start_tag.to_ascii_lowercase();
    let end = end_tag.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut output = String::new();
    while let Some(relative_start) = lower[cursor..].find(&start) {
        let absolute_start = cursor + relative_start;
        output.push_str(&source[cursor..absolute_start]);
        if let Some(relative_end) = lower[absolute_start..].find(&end) {
            cursor = absolute_start + relative_end + end.len();
        } else {
            cursor = source.len();
            break;
        }
    }
    output.push_str(&source[cursor..]);
    output
}

fn strip_markup(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut inside = false;
    for ch in source.chars() {
        match ch {
            '<' => {
                inside = true;
                output.push(' ');
            }
            '>' => {
                inside = false;
                output.push(' ');
            }
            _ if !inside => output.push(ch),
            _ => {}
        }
    }
    output
}

fn collapse_whitespace(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut last_was_space = false;
    for ch in source.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                output.push(' ');
                last_was_space = true;
            }
        } else {
            output.push(ch);
            last_was_space = false;
        }
    }
    output.trim().to_owned()
}

fn trimmed_at_boundary(source: &str, limit: usize) -> String {
    if source.len() <= limit {
        return source.to_owned();
    }
    let cut = source[..limit].rfind(' ').unwrap_or(limit);
    source[..cut].trim().to_owned()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.match_indices(needle).count()
}

fn count_terms(text: &str, terms: &[&str]) -> usize {
    terms.iter().filter(|term| text.contains(**term)).count()
}

fn extract_tag_text(html: &str, tag: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let start = lower.find(&open)?;
    let content_start = lower[start..].find('>')? + start + 1;
    let end = lower[content_start..].find(&close)? + content_start;
    Some(collapse_whitespace(&html[content_start..end]))
}

fn byte_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f32;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = count as f32 / total;
            -p * p.log2()
        })
        .sum()
}

fn layout_profile(text: &str) -> (f32, f32) {
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(64)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return (0.0, 0.0);
    }
    let max_length = lines
        .iter()
        .map(|line| line.len())
        .max()
        .unwrap_or(1)
        .max(1) as f32;
    let lengths = lines
        .iter()
        .map(|line| line.len() as f32 / max_length)
        .collect::<Vec<_>>();
    let symmetry = if lengths.len() < 2 {
        0.0
    } else {
        let mut score = 0.0f32;
        let mut comparisons = 0usize;
        for index in 0..(lengths.len() / 2) {
            score += 1.0 - (lengths[index] - lengths[lengths.len() - 1 - index]).abs();
            comparisons += 1;
        }
        if comparisons == 0 {
            0.0
        } else {
            (score / comparisons as f32).clamp(0.0, 1.0)
        }
    };
    let collapsed = lines.join(" ");
    let mut histogram = HashMap::<char, usize>::new();
    for ch in collapsed.chars() {
        *histogram.entry(ch).or_insert(0) += 1;
    }
    let total = collapsed.chars().count().max(1) as f32;
    let entropy = histogram
        .values()
        .map(|count| {
            let p = *count as f32 / total;
            -p * p.log2()
        })
        .sum::<f32>();
    (symmetry, entropy.min(4.0))
}

fn categorize_content_type(content_type: &str, url: &str) -> String {
    let normalized = content_type.trim().to_ascii_lowercase();
    let lowered_url = url.to_ascii_lowercase();
    if normalized.starts_with("text/html")
        || lowered_url.ends_with(".html")
        || lowered_url.ends_with(".htm")
        || lowered_url.ends_with('/')
    {
        "html".to_owned()
    } else if normalized.starts_with("image/")
        || lowered_url.ends_with(".png")
        || lowered_url.ends_with(".jpg")
        || lowered_url.ends_with(".jpeg")
        || lowered_url.ends_with(".gif")
        || lowered_url.ends_with(".webp")
        || lowered_url.ends_with(".bmp")
    {
        "image".to_owned()
    } else if normalized.starts_with("video/")
        || lowered_url.ends_with(".mp4")
        || lowered_url.ends_with(".mov")
        || lowered_url.ends_with(".mkv")
        || lowered_url.ends_with(".webm")
    {
        "video".to_owned()
    } else if normalized.starts_with("audio/")
        || lowered_url.ends_with(".mp3")
        || lowered_url.ends_with(".wav")
        || lowered_url.ends_with(".ogg")
        || lowered_url.ends_with(".flac")
        || lowered_url.ends_with(".aac")
    {
        "audio".to_owned()
    } else if normalized.starts_with("text/")
        || lowered_url.ends_with(".txt")
        || lowered_url.ends_with(".md")
        || lowered_url.ends_with(".json")
        || lowered_url.ends_with(".xml")
        || lowered_url.ends_with(".css")
        || lowered_url.ends_with(".js")
    {
        "text".to_owned()
    } else {
        "binary".to_owned()
    }
}

fn host_label(url: &str) -> String {
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    stripped.split('/').next().unwrap_or(url).to_owned()
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for item in items {
        if !item.trim().is_empty() && !output.iter().any(|existing: &String| existing == &item) {
            output.push(item);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_html_text_removes_tags() {
        let text = BrowserInspector::strip_html_text(
            "<html><body><script>x</script><h1>Hallo Welt</h1></body></html>",
            120,
        );
        assert!(text.contains("Hallo Welt"));
        assert!(!text.contains("<h1>"));
    }

    #[test]
    fn fake_news_terms_raise_suspicion() {
        let payload = DownloadPayload {
            final_url: "https://example.org/news".to_owned(),
            status_code: 200,
            headers: HashMap::from([("content-type".to_owned(), "text/html".to_owned())]),
            content_type: "text/html".to_owned(),
            content_length: 128,
            raw_bytes: br#"<html><title>Breaking</title><body>Unglaublich exklusive geheime Wahrheit</body></html>"#.to_vec(),
            secure: true,
        };
        let result = BrowserInspector::analyze_download(
            "https://example.org/news",
            payload,
            &BrowserProbePolicy::default(),
        );
        assert!(result.risk_score > 0.0);
        assert!(matches!(
            result.risk_label.as_str(),
            "SUSPICIOUS" | "CRITICAL"
        ));
    }
}
