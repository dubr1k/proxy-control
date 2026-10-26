//! Counter arithmetic: reset-safe deltas and per-client rates (`metrics/rates.py`).

use std::collections::VecDeque;

use indexmap::IndexMap;
use serde_json::Value;

use crate::pyfloat;

/// The growth since `previous`. First sight is a baseline (`None`, no spike); a lower reading is
/// a counter reset, so the growth is the reading itself.
pub fn fold(previous: Option<f64>, reading: f64) -> Option<f64> {
    let previous = previous?;
    Some(if reading >= previous { reading - previous } else { reading })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClientRate {
    pub up_bps: Option<f64>,
    pub down_bps: Option<f64>,
    pub total_bps: f64,
    pub up_delta: f64,
    pub down_delta: f64,
    pub total_delta: f64,
    pub seen: f64,
}

/// One reading of a client's counters; `up`/`down` directional, `total` combined (Telemt).
/// The values are the raw JSON the manager sent (Python's `_number` decides what counts).
#[derive(Debug, Clone, Copy, Default)]
pub struct Reading<'a> {
    pub up: Option<&'a Value>,
    pub down: Option<&'a Value>,
    pub total: Option<&'a Value>,
}

type Key = (String, String);
type Last = (Option<f64>, Option<f64>, Option<f64>, f64);
type WindowRow = (f64, Option<f64>, Option<f64>, Option<f64>);

/// Per-client rates from cumulative counters, keyed by (protocol, username). Time is monotonic
/// seconds supplied by the caller. A client unseen for `forget_after` seconds is dropped.
#[derive(Debug, Clone)]
pub struct ClientRates {
    pub forget_after: f64,
    last: IndexMap<Key, Last>,
    rate: IndexMap<Key, ClientRate>,
    window: IndexMap<Key, (f64, VecDeque<WindowRow>)>,
}

impl Default for ClientRates {
    fn default() -> Self {
        Self::new(600.0)
    }
}

impl ClientRates {
    pub fn new(forget_after: f64) -> Self {
        Self { forget_after, last: IndexMap::new(), rate: IndexMap::new(), window: IndexMap::new() }
    }

    /// Feeds one reading; the new rate, or `None` for the baseline reading. `window` averages
    /// the rate over that many seconds instead of the last interval (NaiveProxy's bursts).
    pub fn update(
        &mut self,
        protocol: &str,
        username: &str,
        now: f64,
        reading: Reading<'_>,
        window: Option<f64>,
    ) -> Option<ClientRate> {
        let key = (protocol.to_string(), username.to_string());
        let up = pyfloat::num(reading.up);
        let down = pyfloat::num(reading.down);
        let mut total = pyfloat::num(reading.total);
        if total.is_none() {
            if let (Some(up), Some(down)) = (up, down) {
                total = Some(up + down);
            }
        }
        let previous = self.last.insert(key.clone(), (up, down, total, now));
        let (p_up, p_down, p_total, then) = previous?;
        let dt = now - then;
        if dt <= 0.0 {
            return self.rate.get(&key).copied();
        }
        let d_up = up.and_then(|up| fold(p_up, up));
        let d_down = down.and_then(|down| fold(p_down, down));
        let Some(mut d_total) = total.and_then(|total| fold(p_total, total)) else {
            return self.rate.get(&key).copied();
        };
        if let (Some(d_up), Some(d_down)) = (d_up, d_down) {
            d_total = d_up + d_down;
        }
        let mut span = dt;
        let mut d_span = (d_up, d_down, Some(d_total));
        if let Some(window) = window {
            let (started, history) = self.window.entry(key.clone()).or_insert_with(|| (then, VecDeque::new()));
            history.push_back((now, d_up, d_down, Some(d_total)));
            while history.front().is_some_and(|row| row.0 <= now - window) {
                history.pop_front();
            }
            span = dt.max(window.min(now - *started));
            let column = |pick: fn(&WindowRow) -> Option<f64>| {
                if history.iter().all(|row| pick(row).is_none()) {
                    None
                } else {
                    Some(history.iter().fold(0.0, |sum, row| sum + pick(row).unwrap_or(0.0)))
                }
            };
            d_span = (column(|row| row.1), column(|row| row.2), column(|row| row.3));
        }
        let rate = ClientRate {
            up_bps: d_span.0.map(|value| value / span),
            down_bps: d_span.1.map(|value| value / span),
            total_bps: d_span.2.unwrap_or(0.0) / span,
            up_delta: d_up.unwrap_or(0.0),
            down_delta: d_down.unwrap_or(0.0),
            total_delta: d_total,
            seen: now,
        };
        self.rate.insert(key, rate);
        Some(rate)
    }

    /// The rates of a protocol's clients refreshed within `max_age` seconds, in first-rated order.
    pub fn current(&self, protocol: &str, now: f64, max_age: f64) -> Vec<(String, ClientRate)> {
        self.rate
            .iter()
            .filter(|((proto, _), rate)| proto == protocol && now - rate.seen <= max_age)
            .map(|((_, user), rate)| (user.clone(), *rate))
            .collect()
    }

    pub fn prune(&mut self, now: f64) {
        let gone: Vec<Key> =
            self.last.iter().filter(|(_, value)| now - value.3 > self.forget_after).map(|(k, _)| k.clone()).collect();
        for key in gone {
            self.last.shift_remove(&key);
            self.rate.shift_remove(&key);
            self.window.shift_remove(&key);
        }
    }

    pub fn len(&self) -> usize {
        self.last.len()
    }

    pub fn is_empty(&self) -> bool {
        self.last.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn updown(
        rates: &mut ClientRates,
        p: &str,
        u: &str,
        now: f64,
        up: Value,
        down: Value,
        w: Option<f64>,
    ) -> Option<ClientRate> {
        rates.update(p, u, now, Reading { up: Some(&up), down: Some(&down), total: None }, w)
    }

    // test_fold_treats_a_lower_reading_as_a_reset_and_first_sight_as_baseline
    #[test]
    fn fold_treats_a_lower_reading_as_a_reset_and_first_sight_as_baseline() {
        assert_eq!(fold(None, 500.0), None);
        assert_eq!(fold(Some(100.0), 160.0), Some(60.0));
        assert_eq!(fold(Some(1000.0), 40.0), Some(40.0));
    }

    // test_a_windowed_rate_spreads_a_burst_over_the_window_and_decays_to_zero
    #[test]
    fn a_windowed_rate_spreads_a_burst_over_the_window_and_decays_to_zero() {
        let mut rates = ClientRates::default();
        let w = Some(60.0);
        assert!(updown(&mut rates, "naive", "nina", 0.0, json!(0), json!(0), w).is_none());
        let quiet = updown(&mut rates, "naive", "nina", 15.0, json!(0), json!(0), w).unwrap();
        assert_eq!((quiet.up_bps, quiet.down_bps), (Some(0.0), Some(0.0)));
        let burst = updown(&mut rates, "naive", "nina", 30.0, json!(3000), json!(60000), w).unwrap();
        assert_eq!((burst.up_bps, burst.down_bps), (Some(100.0), Some(2000.0)));
        let later = updown(&mut rates, "naive", "nina", 45.0, json!(3000), json!(60000), w).unwrap();
        assert_eq!((later.up_bps, later.down_bps), (Some(3000.0 / 45.0), Some(60000.0 / 45.0)));
        let gone = updown(&mut rates, "naive", "nina", 100.0, json!(3000), json!(60000), w).unwrap();
        assert_eq!((gone.up_bps, gone.down_bps), (Some(0.0), Some(0.0)));
        assert_eq!(gone.up_delta, 0.0);
    }

    // test_client_rates_baseline_reset_and_forgetting
    #[test]
    fn client_rates_baseline_reset_and_forgetting() {
        let mut rates = ClientRates::new(600.0);
        assert!(updown(&mut rates, "trusttunnel", "alice", 0.0, json!(1000), json!(5000), None).is_none());
        let rate = updown(&mut rates, "trusttunnel", "alice", 2.0, json!(1400), json!(5800), None).unwrap();
        assert_eq!((rate.up_bps, rate.down_bps, rate.total_bps), (Some(200.0), Some(400.0), 600.0));
        let reset = updown(&mut rates, "trusttunnel", "alice", 4.0, json!(100), json!(200), None).unwrap();
        assert_eq!((reset.up_delta, reset.down_delta), (100.0, 200.0));
        let total = json!(10);
        assert!(rates
            .update("mtproxy", "bob", 0.0, Reading { total: Some(&total), ..Reading::default() }, None)
            .is_none());
        let total = json!(60);
        let combined = rates.update("mtproxy", "bob", 5.0, Reading { total: Some(&total), ..Reading::default() }, None);
        assert_eq!(combined.unwrap().up_bps, None);
        assert_eq!(rates.len(), 2);
        rates.prune(5.0 + 601.0);
        assert_eq!(rates.len(), 0);
    }

    #[test]
    fn bools_strings_and_negatives_are_not_counters() {
        let mut rates = ClientRates::default();
        assert!(updown(&mut rates, "naive", "x", 0.0, json!(true), json!("5"), None).is_none());
        // no usable total on either reading: the previous rate (none) stands
        assert!(updown(&mut rates, "naive", "x", 1.0, json!(-1), json!(null), None).is_none());
    }
}
