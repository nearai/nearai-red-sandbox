//! Glob matching for the `glob` tool, run on the host over the guest's
//! file listing. Supports `**`, `*`, `?`, `[abc]`, `[a-z]`, `[!x]` and
//! `{a,b}`. `*` and `?` never match `/`; `**/` also matches zero directories.

/// Expand `{a,b}` alternatives (nested allowed) into plain patterns.
fn expand_braces(p: &str) -> Vec<String> {
    let b = p.as_bytes();
    let Some(open) = b.iter().position(|&c| c == b'{') else { return vec![p.to_string()] };
    let mut depth = 0;
    let mut close = None;
    let mut commas = vec![];
    for (i, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            b',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let Some(close) = close else { return vec![p.to_string()] };
    let (pre, post) = (&p[..open], &p[close + 1..]);
    let mut bounds = vec![open];
    bounds.extend(&commas);
    bounds.push(close);
    let mut out = vec![];
    for w in bounds.windows(2) {
        let alt = &p[w[0] + 1..w[1]];
        out.extend(expand_braces(&format!("{pre}{alt}{post}")));
    }
    out
}

fn class(p: &[char], mut i: usize, c: char) -> Option<(bool, usize)> {
    // p[i] == '['
    i += 1;
    let negate = i < p.len() && (p[i] == '!' || p[i] == '^');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() && (first || p[i] != ']') {
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if p[i] <= c && c <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if p[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= p.len() {
        return None; // unterminated: treat '[' literally
    }
    Some((matched != negate && c != '/', i + 1))
}

fn m(p: &[char], s: &[char]) -> bool {
    let (mut pi, mut si) = (0, 0);
    // Backtrack points for a single `*`.
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() || pi < p.len() {
        if pi < p.len() {
            if p[pi] == '*' && pi + 1 < p.len() && p[pi + 1] == '*' {
                // `**`, optionally followed by `/`: match any run, including `/`.
                let mut rest = pi + 2;
                let slash = rest < p.len() && p[rest] == '/';
                if slash {
                    rest += 1;
                }
                // Zero directories, or any prefix ending at a `/` (or anywhere if no slash follows).
                if m(&p[rest..], &s[si..]) {
                    return true;
                }
                for k in si..s.len() {
                    if (!slash || s[k] == '/') && m(&p[rest..], &s[k + 1..]) {
                        return true;
                    }
                }
                return false;
            }
            match p[pi] {
                '*' => {
                    star = Some((pi, si));
                    pi += 1;
                    continue;
                }
                '?' if si < s.len() && s[si] != '/' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                '[' if si < s.len() => match class(p, pi, s[si]) {
                    Some((true, next)) => {
                        pi = next;
                        si += 1;
                        continue;
                    }
                    Some((false, _)) => {}
                    None if s[si] == '[' => {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                    None => {}
                },
                ch if si < s.len() && ch == s[si] && ch != '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, ss)) if ss < s.len() && s[ss] != '/' => {
                star = Some((sp, ss + 1));
                pi = sp + 1;
                si = ss + 1;
            }
            _ => return false,
        }
    }
    true
}

pub fn glob_match(pattern: &str, path: &str) -> bool {
    let s: Vec<char> = path.chars().collect();
    expand_braces(pattern).iter().any(|p| m(&p.chars().collect::<Vec<_>>(), &s))
}

#[cfg(test)]
mod tests {
    use super::glob_match as g;

    #[test]
    fn stars_and_double_stars() {
        assert!(g("*.ts", "a.ts"));
        assert!(!g("*.ts", "src/a.ts"));
        assert!(g("**/*.ts", "a.ts"));
        assert!(g("**/*.ts", "src/deep/a.ts"));
        assert!(!g("**/*.ts", "src/a.js"));
        assert!(g("src/**", "src/a/b/c"));
        assert!(g("src/**/x.rs", "src/x.rs"));
        assert!(g("src/**/x.rs", "src/a/b/x.rs"));
        assert!(!g("src/**/x.rs", "lib/x.rs"));
        assert!(g("a*b*c", "aXXbYYc"));
        assert!(!g("a*c", "ab/c"));
    }

    #[test]
    fn classes_question_marks_and_braces() {
        assert!(g("f?.txt", "f1.txt"));
        assert!(!g("f?.txt", "f/.txt"));
        assert!(g("[a-c]x", "bx"));
        assert!(!g("[!a-c]x", "bx"));
        assert!(g("[!a-c]x", "dx"));
        assert!(g("*.{ts,tsx}", "a.tsx"));
        assert!(g("*.{ts,tsx}", "a.ts"));
        assert!(!g("*.{ts,tsx}", "a.js"));
        assert!(g("{src,lib}/**/*.{rs,toml}", "lib/a/Cargo.toml"));
        assert!(g("[", "["));
    }
}
