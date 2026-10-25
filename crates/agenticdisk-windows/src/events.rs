//! Event Log queries through wevtapi (EvtQuery/EvtNext/EvtRender), without PowerShell.

use windows::Win32::System::EventLog::*;
use windows::core::{HSTRING, PCWSTR};

#[derive(Debug, Clone)]
pub struct Event {
    pub id: u32,
    pub provider: String,
    /// ISO 8601 UTC, e.g. "2026-10-20T13:45:12.1234567Z".
    pub time: String,
    /// `<Data Name="x">value</Data>` pairs, in order (unnamed data gets an empty name).
    pub data: Vec<(String, String)>,
}

impl Event {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.data.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    pub fn date(&self) -> &str {
        self.time.get(..10).unwrap_or(&self.time)
    }
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn parse(xml: &str) -> Option<Event> {
    let id = between(xml, "<EventID", "</EventID>")?.rsplit('>').next()?.trim().parse().ok()?;
    let provider =
        between(xml, "<Provider Name='", "'").or_else(|| between(xml, "<Provider Name=\"", "\""))?.to_string();
    let time =
        between(xml, "SystemTime='", "'").or_else(|| between(xml, "SystemTime=\"", "\"")).unwrap_or("").to_string();
    let mut data = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Data") {
        rest = &rest[start + 5..];
        let Some(close) = rest.find('>') else { break };
        let attrs = &rest[..close];
        if attrs.ends_with('/') {
            rest = &rest[close + 1..];
            continue;
        }
        let name = between(attrs, "Name='", "'").or_else(|| between(attrs, "Name=\"", "\"")).unwrap_or("").to_string();
        let body = &rest[close + 1..];
        let Some(end) = body.find("</Data>") else { break };
        data.push((name, unescape(&body[..end])));
        rest = &body[end..];
    }
    Some(Event { id, provider, time, data })
}

/// Newest first. `xpath` is a standard event filter, e.g.
/// `*[System[(EventID=41) and TimeCreated[timediff(@SystemTime) <= 7776000000]]]`.
pub fn query(channel: &str, xpath: &str, max: usize) -> Result<Vec<Event>, String> {
    let mut out = Vec::new();
    // SAFETY: every handle returned by EvtQuery/EvtNext is closed exactly once below; the render
    // buffer is sized from the first call's `used` before the second call writes into it.
    unsafe {
        let results = EvtQuery(
            None,
            PCWSTR(HSTRING::from(channel).as_ptr()),
            PCWSTR(HSTRING::from(xpath).as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
        .map_err(|e| format!("{channel}: {}", e.message()))?;
        let mut handles = [0isize; 64];
        'outer: while out.len() < max {
            let mut returned = 0u32;
            if EvtNext(results, &mut handles, 2000, 0, &mut returned).is_err() || returned == 0 {
                break;
            }
            for &h in &handles[..returned as usize] {
                let event = EVT_HANDLE(h);
                let mut used = 0u32;
                let mut props = 0u32;
                let _ = EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut props);
                let mut buffer = vec![0u16; used as usize / 2 + 1];
                let rendered = EvtRender(
                    None,
                    event,
                    EvtRenderEventXml.0,
                    (buffer.len() * 2) as u32,
                    Some(buffer.as_mut_ptr().cast()),
                    &mut used,
                    &mut props,
                );
                let _ = EvtClose(event);
                if rendered.is_ok() {
                    let xml = String::from_utf16_lossy(&buffer[..(used as usize / 2).min(buffer.len())]);
                    if let Some(e) = parse(xml.trim_end_matches('\0')) {
                        out.push(e);
                    }
                }
                if out.len() >= max {
                    break 'outer;
                }
            }
        }
        let _ = EvtClose(results);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_event_xml() {
        let xml = r#"<Event><System><Provider Name='Microsoft-Windows-WER-SystemErrorReporting' Guid='{x}'/><EventID Qualifiers='16384'>1001</EventID><TimeCreated SystemTime='2026-10-20T13:45:12.1Z'/></System><EventData><Data Name='param1'>0x00000133 (0x1, 0x1e00)</Data><Data Name='param2'>C:\WINDOWS\Minidump\x.dmp</Data><Data Name='empty'/></EventData></Event>"#;
        let e = super::parse(xml).unwrap();
        assert_eq!(e.id, 1001);
        assert_eq!(e.provider, "Microsoft-Windows-WER-SystemErrorReporting");
        assert_eq!(e.get("param1"), Some("0x00000133 (0x1, 0x1e00)"));
        assert_eq!(e.date(), "2026-10-20");
    }
}
