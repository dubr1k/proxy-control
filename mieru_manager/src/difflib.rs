//! `difflib.unified_diff(a, b, n=0)` without its header lines, as the egress plan reports
//! the change: Python's `SequenceMatcher` (no junk function, autojunk on) ported as is, so
//! the lines it picks as matching are the ones Python picked.

use std::collections::{HashMap, HashSet};

struct Matcher<'a> {
    a: &'a [String],
    b: &'a [String],
    b2j: HashMap<&'a str, Vec<usize>>,
}

impl<'a> Matcher<'a> {
    fn new(a: &'a [String], b: &'a [String]) -> Self {
        let mut b2j: HashMap<&str, Vec<usize>> = HashMap::new();
        for (j, line) in b.iter().enumerate() {
            b2j.entry(line.as_str()).or_default().push(j);
        }
        // Popular elements (more than 1% of a long `b`) are not indexed.
        if b.len() >= 200 {
            let ntest = b.len() / 100 + 1;
            let popular: HashSet<&str> = b2j.iter().filter(|(_, idxs)| idxs.len() > ntest).map(|(k, _)| *k).collect();
            for line in popular {
                b2j.remove(line);
            }
        }
        Self { a, b, b2j }
    }

    fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> (usize, usize, usize) {
        let (a, b) = (self.a, self.b);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, line) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(indices) = self.b2j.get(line.as_str()) {
                for &j in indices {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = j.checked_sub(1).and_then(|p| j2len.get(&p)).copied().unwrap_or(0) + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }
        // No junk: extend by equal (popular) elements on both ends.
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
        blocks.sort_unstable();
        let mut merged = Vec::new();
        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        for (i2, j2, k2) in blocks {
            if i1 + k1 == i2 && j1 + k1 == j2 {
                k1 += k2;
            } else {
                if k1 > 0 {
                    merged.push((i1, j1, k1));
                }
                (i1, j1, k1) = (i2, j2, k2);
            }
        }
        if k1 > 0 {
            merged.push((i1, j1, k1));
        }
        merged.push((la, lb, 0));
        merged
    }
}

/// The `-`/`+` lines of `unified_diff(a, b, n=0)`: with no context every equal run is cut to
/// nothing, so what remains is each change in order, its removed lines before its added ones.
pub fn changed_lines(a: &[String], b: &[String]) -> Vec<String> {
    let matcher = Matcher::new(a, b);
    let (mut i, mut j) = (0, 0);
    let mut lines = Vec::new();
    for (ai, bj, size) in matcher.matching_blocks() {
        lines.extend(a[i..ai].iter().map(|line| format!("-{line}")));
        lines.extend(b[j..bj].iter().map(|line| format!("+{line}")));
        (i, j) = (ai + size, bj + size);
    }
    lines
}
