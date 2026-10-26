//! `difflib.SequenceMatcher` (no junk function, `autojunk=True`) and the changed lines of
//! `difflib.unified_diff(..., n=0)` — the egress plan's diff, in Python's exact order.

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
            b2j.entry(*line).or_default().push(index);
        }
        if b.len() >= 200 {
            let limit = b.len() / 100 + 1;
            b2j.retain(|_, indexes| indexes.len() <= limit);
        }
        Self { a, b, b2j }
    }

    fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> (usize, usize, usize) {
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for i in alo..ahi {
            let mut next: HashMap<usize, usize> = HashMap::new();
            for &j in self.b2j.get(self.a[i]).map(Vec::as_slice).unwrap_or(&[]) {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j.checked_sub(1).and_then(|p| j2len.get(&p)).copied().unwrap_or(0) + 1;
                next.insert(j, k);
                if k > bestsize {
                    (besti, bestj, bestsize) = (i + 1 - k, j + 1 - k, k);
                }
            }
            j2len = next;
        }
        while besti > alo && bestj > blo && self.a[besti - 1] == self.b[bestj - 1] {
            (besti, bestj, bestsize) = (besti - 1, bestj - 1, bestsize + 1);
        }
        while besti + bestsize < ahi && bestj + bestsize < bhi && self.a[besti + bestsize] == self.b[bestj + bestsize] {
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
        let mut merged = Vec::new();
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

/// The `-`/`+` lines `unified_diff(a, b, n=0, lineterm="")` yields, in order, with the
/// `---`, `+++` and `@@` lines left out the way the manager filters them.
pub fn changed_lines(a: &[&str], b: &[&str]) -> Vec<String> {
    let matcher = Matcher::new(a, b);
    let mut out = Vec::new();
    for (tag, i1, i2, j1, j2) in matcher.opcodes() {
        if tag == "replace" || tag == "delete" {
            out.extend(a[i1..i2].iter().map(|line| format!("-{line}")));
        }
        if tag == "replace" || tag == "insert" {
            out.extend(b[j1..j2].iter().map(|line| format!("+{line}")));
        }
    }
    out.retain(|line| !(line.starts_with("---") || line.starts_with("+++") || line.starts_with("@@")));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_lines_follow_python_unified_diff() {
        // [line for line in difflib.unified_diff(a, b, n=0, lineterm="") if not header]
        assert_eq!(changed_lines(&["x", "a", "b"], &["a", "c", "b", "d"]), ["-x", "+c", "+d"]);
        assert_eq!(changed_lines(&[], &["# BEGIN", "upstream u", "# END"]), ["+# BEGIN", "+upstream u", "+# END"]);
        assert_eq!(changed_lines(&["a", "b"], &["c"]), ["-a", "-b", "+c"]);
        assert_eq!(changed_lines(&["--x"], &[]), Vec::<String>::new());
        assert_eq!(changed_lines(&["same"], &["same"]), Vec::<String>::new());
    }
}
