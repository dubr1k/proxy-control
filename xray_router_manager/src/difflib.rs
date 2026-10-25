//! `difflib.unified_diff(a, b, n=0)` over lines, as the plan's `diff` showed it: Python's
//! `SequenceMatcher` (no junk function, the automatic "popular line" heuristic for 200+ lines)
//! decides which lines changed, so the same two documents give the same lines.

use std::collections::HashMap;

struct Matcher<'a> {
    a: &'a [&'a str],
    b: &'a [&'a str],
    b2j: HashMap<&'a str, Vec<usize>>,
}

impl<'a> Matcher<'a> {
    fn new(a: &'a [&'a str], b: &'a [&'a str]) -> Self {
        let mut b2j: HashMap<&str, Vec<usize>> = HashMap::new();
        for (index, line) in b.iter().enumerate() {
            b2j.entry(line).or_default().push(index);
        }
        if b.len() >= 200 {
            let ntest = b.len() / 100 + 1;
            b2j.retain(|_, indices| indices.len() <= ntest);
        }
        Self { a, b, b2j }
    }

    fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> (usize, usize, usize) {
        let (a, b) = (self.a, self.b);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, line) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut next: HashMap<usize, usize> = HashMap::new();
            for &j in self.b2j.get(line).map(Vec::as_slice).unwrap_or(&[]) {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = if j > 0 { j2len.get(&(j - 1)).copied().unwrap_or(0) } else { 0 } + 1;
                next.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
            j2len = next;
        }
        // No junk: only the extension over equal (popular) lines applies.
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi && bestj + bestsize < bhi && a[besti + bestsize] == b[bestj + bestsize] {
            bestsize += 1;
        }
        (besti, bestj, bestsize)
    }

    fn matching_blocks(&self) -> Vec<(usize, usize, usize)> {
        let (la, lb) = (self.a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks = Vec::new();
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.find_longest_match(alo, ahi, blo, bhi);
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
        blocks.sort();
        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        let mut collapsed = Vec::new();
        for (i2, j2, k2) in blocks {
            if i1 + k1 == i2 && j1 + k1 == j2 {
                k1 += k2;
            } else {
                if k1 > 0 {
                    collapsed.push((i1, j1, k1));
                }
                (i1, j1, k1) = (i2, j2, k2);
            }
        }
        if k1 > 0 {
            collapsed.push((i1, j1, k1));
        }
        collapsed.push((la, lb, 0));
        collapsed
    }

    fn opcodes(&self) -> Vec<(&'static str, usize, usize, usize, usize)> {
        let (mut i, mut j) = (0, 0);
        let mut answer = Vec::new();
        for (ai, bj, size) in self.matching_blocks() {
            let tag = if i < ai && j < bj {
                "replace"
            } else if i < ai {
                "delete"
            } else if j < bj {
                "insert"
            } else {
                ""
            };
            if !tag.is_empty() {
                answer.push((tag, i, ai, j, bj));
            }
            (i, j) = (ai + size, bj + size);
            if size > 0 {
                answer.push(("equal", ai, i, bj, j));
            }
        }
        answer
    }
}

/// The change lines of `unified_diff(a, b, lineterm="", n=0)` — what the plan showed after
/// dropping the `---`, `+++` and `@@` lines.
pub fn changed_lines(a: &[&str], b: &[&str]) -> Vec<String> {
    let matcher = Matcher::new(a, b);
    let mut codes = matcher.opcodes();
    if codes.is_empty() {
        codes.push(("equal", 0, 1, 0, 1));
    }
    // n = 0: the equal ranges around and between changes contribute no lines; a group of nothing
    // but an equal range is not a hunk.
    let only_equal = codes.iter().all(|code| code.0 == "equal");
    let mut lines = Vec::new();
    if only_equal {
        return lines;
    }
    for (tag, i1, i2, j1, j2) in codes {
        if matches!(tag, "replace" | "delete") {
            lines.extend(a[i1..i2].iter().map(|line| format!("-{line}")));
        }
        if matches!(tag, "replace" | "insert") {
            lines.extend(b[j1..j2].iter().map(|line| format!("+{line}")));
        }
    }
    lines.retain(|line| !(line.starts_with("---") || line.starts_with("+++") || line.starts_with("@@")));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_changes() {
        assert_eq!(changed_lines(&["a", "b", "c"], &["a", "x", "c"]), ["-b", "+x"]);
        assert!(changed_lines(&["a"], &["a"]).is_empty());
        assert!(changed_lines(&[], &[]).is_empty());
        assert_eq!(changed_lines(&[], &["a"]), ["+a"]);
    }

    const GOLDEN: &str = include_str!("../testdata/diff.json");

    /// The plan's `diff` for the golden pairs — 200+ line documents included, where the
    /// popular-line heuristic decides — is the Python manager's, line for line.
    #[test]
    fn golden_diffs_match_the_python_plan() {
        let golden: Vec<serde_json::Value> = serde_json::from_str(GOLDEN).unwrap();
        for entry in &golden {
            let before = crate::pyjson::dumps(&entry["before"], &crate::pyjson::INDENT1_SORTED);
            let after = crate::pyjson::dumps(&entry["after"], &crate::pyjson::INDENT1_SORTED);
            let (before, after): (Vec<&str>, Vec<&str>) = (before.split('\n').collect(), after.split('\n').collect());
            let expected: Vec<String> = serde_json::from_value(entry["diff"].clone()).unwrap();
            assert_eq!(changed_lines(&before, &after), expected, "{}", entry["after"]);
        }
        assert!(golden.iter().any(|entry| entry["diff"].as_array().unwrap().len() > 50));
    }
}
