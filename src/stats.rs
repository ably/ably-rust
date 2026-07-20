use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::Deserialize;

/// Ably application statistics for a single interval (TS1/TS12), retrieved from
/// the [REST stats endpoint].
///
/// As of specification version 2.2 the old deeply-nested per-type structure is
/// deprecated in favour of a flat `entries` map, so this type exposes the
/// flattened API only.
///
/// [REST stats endpoint]: https://ably.com/docs/general/statistics
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Stats {
    /// TS12a: the interval this datapoint covers, e.g. `"2024-01-01:00:00"`.
    pub interval_id: String,
    /// TS12c: the granularity the stats are aggregated by. Taken from the JSON
    /// `unit` field, not derived from `interval_id`.
    pub unit: StatsIntervalGranularity,
    /// TS12q: for an interval still in progress (e.g. the current month), the
    /// last sub-interval included, in `yyyy-mm-dd:hh:mm` format.
    pub in_progress: Option<String>,
    /// TS12r: the flattened statistics entries, keyed by dotted metric path
    /// (e.g. `"messages.all.all.count"`). The spec types the values as
    /// integers; rate entries (e.g. `"peakRates.messages"`) are fractional, so
    /// they are represented as `f64`.
    pub entries: HashMap<String, f64>,
    /// TS12s: the JSON schema URI for this datapoint.
    pub schema: Option<String>,
    /// TS12t: the id of the Ably application these stats are for.
    pub app_id: Option<String>,
}

impl Stats {
    /// TS12p: the interval start time, parsed from `interval_id`. Returns
    /// `None` if the id is not a recognised interval format.
    pub fn interval_time(&self) -> Option<DateTime<Utc>> {
        parse_interval_id(&self.interval_id)
    }
}

/// TS12c: the period stats are aggregated by.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatsIntervalGranularity {
    #[default]
    Minute,
    Hour,
    Day,
    Month,
}

/// Parse an Ably stats interval id into its start time. The format depends on
/// the granularity: `yyyy-mm` (month), `yyyy-mm-dd` (day), `yyyy-mm-dd:hh`
/// (hour), or `yyyy-mm-dd:hh:mm` (minute).
fn parse_interval_id(id: &str) -> Option<DateTime<Utc>> {
    let mut parts = id.split(':');
    let date_part = parts.next()?;
    // Missing hour/minute segments default to 0; a present-but-unparsable
    // segment fails the whole parse.
    let hour: u32 = match parts.next() {
        Some(h) => h.parse().ok()?,
        None => 0,
    };
    let minute: u32 = match parts.next() {
        Some(m) => m.parse().ok()?,
        None => 0,
    };

    let date = if date_part.matches('-').count() == 1 {
        // `yyyy-mm` — the start of the month.
        NaiveDate::parse_from_str(&format!("{date_part}-01"), "%Y-%m-%d").ok()?
    } else {
        NaiveDate::parse_from_str(date_part, "%Y-%m-%d").ok()?
    };
    let naive = date.and_hms_opt(hour, minute, 0)?;
    Some(Utc.from_utc_datetime(&naive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_time_parses_each_granularity() {
        let cases = [
            ("2024-03", (2024, 3, 1, 0, 0)),
            ("2024-03-15", (2024, 3, 15, 0, 0)),
            ("2024-03-15:09", (2024, 3, 15, 9, 0)),
            ("2024-03-15:09:30", (2024, 3, 15, 9, 30)),
        ];
        for (id, (y, mo, d, h, mi)) in cases {
            let t = parse_interval_id(id).unwrap_or_else(|| panic!("parse {id}"));
            assert_eq!(t, Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap(), "{id}");
        }
        assert!(parse_interval_id("not-an-interval").is_none());
    }
}
