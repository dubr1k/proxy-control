//! In-memory points per series: a fixed-size ring of `(ts, value)` (`metrics/ring.py`).
//!
//! Shared as `Arc<Mutex<SeriesRing>>` between the collector (writer) and the store (reader); a
//! lock is never held across an `.await`.

use std::collections::VecDeque;

use indexmap::IndexMap;

#[derive(Debug, Clone)]
pub struct SeriesRing {
    points: usize,
    series: IndexMap<String, VecDeque<(f64, f64)>>,
}

impl SeriesRing {
    /// `SeriesRing(points)`: at least two points per series.
    pub fn new(points: i64) -> Self {
        Self { points: points.max(2) as usize, series: IndexMap::new() }
    }

    /// The capacity per series.
    pub fn capacity(&self) -> usize {
        self.points
    }

    pub fn append(&mut self, series: &str, ts: f64, value: f64) {
        let points = self.points;
        let ring = self.series.entry(series.to_string()).or_insert_with(|| VecDeque::with_capacity(points));
        if ring.len() == points {
            ring.pop_front();
        }
        ring.push_back((ts, value));
    }

    /// One sample: every series with a value (a `None` leaves a gap).
    pub fn add_sample(&mut self, ts: f64, values: &IndexMap<String, Option<f64>>) {
        for (series, value) in values {
            if let Some(value) = value {
                self.append(series, ts, *value);
            }
        }
    }

    /// The points of a series with `start <= ts <= end`.
    pub fn points_of(&self, series: &str, start: f64, end: f64) -> Vec<(f64, f64)> {
        match self.series.get(series) {
            Some(ring) => ring.iter().filter(|(ts, _)| start <= *ts && *ts <= end).copied().collect(),
            None => Vec::new(),
        }
    }

    /// Every point of a series.
    pub fn all_points(&self, series: &str) -> Vec<(f64, f64)> {
        self.points_of(series, f64::NEG_INFINITY, f64::INFINITY)
    }

    /// The oldest timestamp of one series, or of all of them.
    pub fn oldest(&self, series: Option<&str>) -> Option<f64> {
        let firsts = match series {
            Some(name) => self.series.get(name).and_then(|ring| ring.front()).map(|p| p.0).into_iter().collect(),
            None => self.series.values().filter_map(|ring| ring.front()).map(|p| p.0).collect::<Vec<_>>(),
        };
        firsts.into_iter().reduce(|a, b| if b < a { b } else { a })
    }

    /// The series in first-seen order.
    pub fn series_names(&self) -> Vec<String> {
        self.series.keys().cloned().collect()
    }

    pub fn last(&self, series: &str) -> Option<(f64, f64)> {
        self.series.get(series).and_then(|ring| ring.back()).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_newest_points_and_leaves_gaps() {
        let mut ring = SeriesRing::new(1);
        assert_eq!(ring.capacity(), 2);
        for i in 0..3 {
            ring.append("host.cpu", i as f64, i as f64 * 10.0);
        }
        assert_eq!(ring.all_points("host.cpu"), vec![(1.0, 10.0), (2.0, 20.0)]);
        let mut values = IndexMap::new();
        values.insert("net.rx_bps".to_string(), None);
        values.insert("host.mem".to_string(), Some(4.0));
        ring.add_sample(5.0, &values);
        assert_eq!(ring.series_names(), vec!["host.cpu", "host.mem"]);
        assert_eq!(ring.oldest(None), Some(1.0));
        assert_eq!(ring.oldest(Some("host.mem")), Some(5.0));
        assert_eq!(ring.last("host.mem"), Some((5.0, 4.0)));
        assert_eq!(ring.points_of("host.cpu", 2.0, 2.0), vec![(2.0, 20.0)]);
        assert!(ring.points_of("nope", 0.0, 9.0).is_empty());
    }
}
