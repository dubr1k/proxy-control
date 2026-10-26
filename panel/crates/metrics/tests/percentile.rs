use panel_metrics::store::percentile;

#[test]
fn percentile_is_nearest_rank() {
    let values: Vec<f64> = (1..=100).map(f64::from).collect();
    assert_eq!(percentile(&values, 0.95), Some(95.0));
    assert_eq!(percentile(&[], 0.95), None);
}
