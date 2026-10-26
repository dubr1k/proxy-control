//! Python float arithmetic the meters depend on (`fixtures/floats.json`): `round(x)`,
//! `round(x, 1)`, `round(x, 3)`, `format(x, ".1f")`, `format(x, ".0f")`, `x // 60|900|3600`.

mod common;

use panel_metrics::pyfloat;
use serde_json::Value;

#[test]
fn rounding_formatting_and_floor_division_match_python() {
    let recorded: Value = serde_json::from_str(&common::fixture("floats.json")).unwrap();
    let rows = recorded["rows"].as_array().unwrap();
    assert!(rows.len() > 300);
    for row in rows {
        let x = row["x"].as_f64().unwrap();
        let bits = |key: &str| row[key].as_f64().unwrap().to_bits();
        assert_eq!(pyfloat::round_int(x), row["round0"].as_i64().unwrap(), "round({x})");
        assert_eq!(pyfloat::round_to(x, 1).to_bits(), bits("round1"), "round({x}, 1)");
        assert_eq!(pyfloat::round_to(x, 3).to_bits(), bits("round3"), "round({x}, 3)");
        assert_eq!(pyfloat::fixed(x, 1), row["f1"].as_str().unwrap(), "format({x}, '.1f')");
        assert_eq!(pyfloat::fixed(x, 0), row["f0"].as_str().unwrap(), "format({x}, '.0f')");
        for (key, step) in [("fd60", 60.0), ("fd900", 900.0), ("fd3600", 3600.0)] {
            assert_eq!(pyfloat::floordiv(x, step).to_bits(), bits(key), "{x} // {step}");
        }
    }
}
