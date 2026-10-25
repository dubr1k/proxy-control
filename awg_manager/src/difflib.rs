//! The lines `difflib.unified_diff(a, b, n=0)` prints, minus its `---`/`+++`/`@@` headers: the
//! egress plan's diff. A port of `SequenceMatcher` without junk (the plan compares two documents of
//! a few lines, far below the 200 lines where `autojunk` would start to matter).

use std::collections::HashMap;

/// The longest common block of `a[alo..ahi]` and `b[blo..bhi]`; on ties the earliest in `a`, then
/// in `b`, as `find_longest_match` picks it.
fn longest_match(
    a: &[String],
    b2j: &HashMap<&str, Vec<usize>>,
    (alo, ahi): (usize, usize),
    (blo, bhi): (usize, usize),
) -> (usize, usize, usize) {
    let (mut best_i, mut best_j, mut best_size) = (alo, blo, 0);
    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for (i, line) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut next: HashMap<usize, usize> = HashMap::new();
        for &j in b2j.get(line.as_str()).map(Vec::as_slice).unwrap_or(&[]) {
            if j < blo {
                continue;
            }
            if j >= bhi {
                break;
            }
            let k = j.checked_sub(1).and_then(|prev| j2len.get(&prev)).copied().unwrap_or(0) + 1;
            next.insert(j, k);
            if k > best_size {
                (best_i, best_j, best_size) = (i + 1 - k, j + 1 - k, k);
            }
        }
        j2len = next;
    }
    (best_i, best_j, best_size)
}

fn matching_blocks(a: &[String], b: &[String]) -> Vec<(usize, usize, usize)> {
    let mut b2j: HashMap<&str, Vec<usize>> = HashMap::new();
    for (j, line) in b.iter().enumerate() {
        b2j.entry(line.as_str()).or_default().push(j);
    }
    let mut queue = vec![(0, a.len(), 0, b.len())];
    let mut blocks = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = longest_match(a, &b2j, (alo, ahi), (blo, bhi));
        if k > 0 {
            blocks.push((i, j, k));
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    blocks.sort_unstable();
    let mut merged: Vec<(usize, usize, usize)> = Vec::new();
    for (i, j, k) in blocks {
        match merged.last_mut() {
            Some(last) if last.0 + last.2 == i && last.1 + last.2 == j => last.2 += k,
            _ => merged.push((i, j, k)),
        }
    }
    merged.push((a.len(), b.len(), 0));
    merged
}

/// Every changed line in order: for each replaced, deleted or inserted run the `-` lines of `a`,
/// then the `+` lines of `b`.
pub fn changed_lines(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    for (ai, bj, size) in matching_blocks(a, b) {
        out.extend(a[i..ai].iter().map(|line| format!("-{line}")));
        out.extend(b[j..bj].iter().map(|line| format!("+{line}")));
        (i, j) = (ai + size, bj + size);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(String::from).collect()
    }

    #[test]
    fn diff_of_the_egress_documents_matches_difflib() {
        let direct = lines("{\n \"schema\": 1,\n \"upstream\": null\n}");
        let warp = lines("{\n \"schema\": 1,\n \"upstream\": {\n  \"provider\": \"warp\"\n }\n}");
        let router = lines("{\n \"schema\": 1,\n \"upstream\": {\n  \"provider\": \"router\"\n }\n}");
        assert_eq!(
            changed_lines(&direct, &warp),
            ["- \"upstream\": null", "+ \"upstream\": {", "+  \"provider\": \"warp\"", "+ }"]
        );
        assert_eq!(
            changed_lines(&warp, &direct),
            ["- \"upstream\": {", "-  \"provider\": \"warp\"", "- }", "+ \"upstream\": null"]
        );
        assert_eq!(changed_lines(&warp, &router), ["-  \"provider\": \"warp\"", "+  \"provider\": \"router\""]);
        assert!(changed_lines(&warp, &warp).is_empty());
    }

    #[test]
    fn separate_runs_and_pure_insertions() {
        // difflib.unified_diff("abcd", "xbcy", n=0) and ("ac", "abc", n=0)
        let (a, b) = (lines("a\nb\nc\nd"), lines("x\nb\nc\ny"));
        assert_eq!(changed_lines(&a, &b), ["-a", "+x", "-d", "+y"]);
        assert_eq!(changed_lines(&lines("a\nc"), &lines("a\nb\nc")), ["+b"]);
    }
}
