//! The text of `sshd_config`: enough of OpenSSH's syntax to find where a `Match` block can
//! go and which key files are configured, and the block MassRelay owns.
//!
//! The file is handled as bytes, so everything outside the block is kept exactly.

use std::ops::Range;

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};

const BEGIN: &str = "# BEGIN MassRelay SSH ";
const END: &str = "# END MassRelay SSH ";
const ABOUT: &str = "# MassRelay's key file, for this account's logins from 127.0.0.1. \
                     Removed by massrelay uninstall.";

/// One argument of a directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Token {
    /// As written, quotes included.
    pub raw: String,
    /// As OpenSSH reads it.
    pub value: String,
}

impl Token {
    /// An argument for `value`, which holds no quote, backslash or control character.
    pub(super) fn new(value: &str) -> Self {
        let raw = if value.contains(char::is_whitespace) || value.starts_with('#') {
            format!("\"{value}\"")
        } else {
            value.to_owned()
        };
        Self {
            raw,
            value: value.to_owned(),
        }
    }
}

/// A line's keyword and what follows it, split as OpenSSH splits them.
pub(super) fn directive(line: &str) -> (&str, &str) {
    let line = line.trim_start();
    let (keyword, rest) = match line.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"').unwrap_or((quoted, "")),
        None => {
            let end = line
                .find(|c: char| c.is_whitespace() || c == '=' || c == '"')
                .unwrap_or(line.len());
            line.split_at(end)
        }
    };
    let rest = rest.trim_start();
    (keyword, rest.strip_prefix('=').unwrap_or(rest).trim_start())
}

/// A line's arguments: separated by blanks, optionally quoted or escaped as OpenSSH's
/// `argv_split` has it, ending at a comment.
pub(super) fn tokens(arguments: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = arguments.trim_end().char_indices().peekable();
    while let Some(&(start, first)) = chars.peek() {
        if first.is_whitespace() {
            chars.next();
            continue;
        }
        if first == '#' {
            break;
        }
        let mut value = String::new();
        let mut quote = None;
        let mut end = arguments.trim_end().len();
        while let Some((at, c)) = chars.next() {
            match (quote, c) {
                (_, '\\') => match chars.peek() {
                    Some(&(_, next))
                        if matches!(next, '\'' | '"' | '\\')
                            || (quote.is_none() && next == ' ') =>
                    {
                        value.push(next);
                        chars.next();
                    }
                    _ => value.push('\\'),
                },
                (None, c) if c.is_whitespace() => {
                    end = at;
                    break;
                }
                (None, '"' | '\'') => quote = Some(c),
                (Some(open), c) if c == open => quote = None,
                _ => value.push(c),
            }
        }
        ensure!(
            quote.is_none(),
            "an SSH configuration line has an unterminated quote"
        );
        tokens.push(Token {
            raw: arguments[start..end].to_owned(),
            value,
        });
    }
    Ok(tokens)
}

/// Each line with the bytes it occupies, its newline included.
fn lines(config: &[u8]) -> impl Iterator<Item = (Range<usize>, String)> + '_ {
    let mut start = 0;
    config
        .split_inclusive(|&byte| byte == b'\n')
        .map(move |line| {
            let span = start..start + line.len();
            start = span.end;
            let text = String::from_utf8_lossy(line);
            (span, text.trim_end_matches(['\r', '\n']).to_owned())
        })
}

/// The arguments of every `keyword` line, wherever it is in the file.
pub(super) fn arguments(config: &[u8], keyword: &str) -> Result<Vec<Vec<Token>>> {
    lines(config)
        .filter_map(|(_, line)| {
            let (found, rest) = directive(&line);
            found.eq_ignore_ascii_case(keyword).then(|| tokens(rest))
        })
        .collect()
}

/// What an unedited MassRelay block says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Managed {
    pub user: String,
    pub port: u16,
    pub keys: Vec<Token>,
}

#[derive(Debug)]
pub(super) struct Block {
    /// The profile the block belongs to.
    pub id: String,
    pub span: Range<usize>,
    /// `None` once someone has edited the block.
    pub managed: Option<Managed>,
}

/// The block marker for a profile's key file.
pub(super) fn id(key_file: &str) -> String {
    short_hash(key_file.as_bytes())
}

fn short_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_owned()
}

/// Every MassRelay block. A block whose extent is unclear is an error.
pub(super) fn blocks(config: &[u8]) -> Result<Vec<Block>> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut open: Option<(String, String, usize, Vec<String>)> = None;
    for (span, line) in lines(config) {
        if let Some(marker) = line.strip_prefix(BEGIN) {
            ensure!(open.is_none(), "a MassRelay SSH block has no end marker");
            let (id, hash) = marker.trim().split_once(' ').unwrap_or((marker.trim(), ""));
            open = Some((id.to_owned(), hash.to_owned(), span.start, Vec::new()));
        } else if let Some(marker) = line.strip_prefix(END) {
            let Some((id, hash, start, body)) = open.take() else {
                bail!("a MassRelay SSH block has no begin marker");
            };
            ensure!(
                marker.trim() == id,
                "MassRelay SSH block markers do not match"
            );
            ensure!(
                blocks.iter().all(|block| block.id != id),
                "a MassRelay SSH block appears twice"
            );
            let managed = (short_hash(body.join("\n").as_bytes()) == hash)
                .then(|| parse(&body))
                .flatten();
            blocks.push(Block {
                id,
                span: start..span.end,
                managed,
            });
        } else if let Some((_, _, _, body)) = &mut open {
            body.push(line);
        }
    }
    ensure!(open.is_none(), "a MassRelay SSH block has no end marker");
    Ok(blocks)
}

fn body(user: &str, port: u16, keys: &[Token]) -> Vec<String> {
    let keys: Vec<_> = keys.iter().map(|key| key.raw.as_str()).collect();
    vec![
        ABOUT.to_owned(),
        format!("Match User {user} Address 127.0.0.1 LocalAddress 127.0.0.1 LocalPort {port}"),
        format!("\tAuthorizedKeysFile {}", keys.join(" ")),
        // Whatever is appended to the file later applies to every connection again.
        "Match all".to_owned(),
    ]
}

fn parse(lines: &[String]) -> Option<Managed> {
    let mut words = lines.get(1)?.split(' ');
    let user = words.nth(2)?.to_owned();
    let port = words.next_back()?.parse().ok()?;
    let keys = tokens(directive(lines.get(2)?).1).ok()?;
    (body(&user, port, &keys) == lines).then_some(Managed { user, port, keys })
}

/// The block that gives `user`'s loopback logins on `port` the key files `keys`.
pub(super) fn render(id: &str, user: &str, port: u16, keys: &[Token], newline: &str) -> String {
    let body = body(user, port, keys);
    let hash = short_hash(body.join("\n").as_bytes());
    let mut lines = vec![format!("{BEGIN}{id} {hash}")];
    lines.extend(body);
    lines.push(format!("{END}{id}"));
    lines.join(newline) + newline
}

pub(super) fn newline(config: &[u8]) -> &'static str {
    match config.iter().position(|&byte| byte == b'\n') {
        Some(end) if config[..end].ends_with(b"\r") => "\r\n",
        _ => "\n",
    }
}

/// `config` with `block` after every global setting: before the first `Match` line, or the
/// MassRelay block that holds it, and otherwise at the end. Among `Match` blocks OpenSSH
/// keeps the first value it finds.
pub(super) fn insert(config: &[u8], block: &str) -> Result<Vec<u8>> {
    ensure!(
        !config.contains(&0),
        "the SSH server configuration is not plain text (UTF-16 perhaps)"
    );
    let owned = blocks(config)?;
    let first = lines(config)
        .find(|(_, line)| directive(line).0.eq_ignore_ascii_case("match"))
        .map(|(span, _)| {
            owned
                .iter()
                .find(|block| block.span.contains(&span.start))
                .map_or(span.start, |block| block.span.start)
        });
    let at = first.unwrap_or(config.len());
    let mut updated = config[..at].to_vec();
    if !updated.is_empty() && !updated.ends_with(b"\n") {
        updated.extend_from_slice(newline(config).as_bytes());
    }
    updated.extend_from_slice(block.as_bytes());
    updated.extend_from_slice(&config[at..]);
    Ok(updated)
}

/// `config` with each span replaced. The spans are in order and do not overlap.
pub(super) fn splice(config: &[u8], changes: &[(Range<usize>, String)]) -> Vec<u8> {
    let mut updated = Vec::with_capacity(config.len());
    let mut copied = 0;
    for (span, text) in changes {
        updated.extend_from_slice(&config[copied..span.start]);
        updated.extend_from_slice(text.as_bytes());
        copied = span.end;
    }
    updated.extend_from_slice(&config[copied..]);
    updated
}

/// Whether the file name `name` matches an `Include` component with `*` and `?`.
pub(super) fn matches(pattern: &str, name: &str) -> bool {
    // As glob(3): a leading dot is matched only by one in the pattern.
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let pattern: Vec<_> = pattern.chars().collect();
    let name: Vec<_> = name.chars().collect();
    let (mut p, mut n, mut retry) = (0, 0, None);
    while n < name.len() {
        if pattern.get(p) == Some(&'*') {
            retry = Some((p, n));
            p += 1;
        } else if pattern.get(p).is_some_and(|&c| c == '?' || c == name[n]) {
            p += 1;
            n += 1;
        } else if let Some((star, from)) = retry {
            retry = Some((star, from + 1));
            p = star + 1;
            n = from + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// The values of a setting in `sshd -T` output.
pub(super) fn settings<'a>(output: &'a str, key: &'a str) -> impl Iterator<Item = &'a str> {
    output
        .lines()
        .filter_map(move |line| line.strip_prefix(key)?.strip_prefix(' '))
}

pub(super) fn setting<'a>(output: &'a str, key: &'a str) -> Option<&'a str> {
    settings(output, key).next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(values: &[&str]) -> Vec<Token> {
        values.iter().map(|value| Token::new(value)).collect()
    }

    #[test]
    fn arguments_read_as_openssh_splits_them_and_keep_their_spelling() -> Result<()> {
        let read = tokens(r#"one "two words" 'three' fo\"ur C:\keys\\x a#b # comment"#)?;
        let values: Vec<_> = read.iter().map(|token| token.value.as_str()).collect();
        assert_eq!(
            values,
            ["one", "two words", "three", "fo\"ur", r"C:\keys\x", "a#b"]
        );
        assert_eq!(read[1].raw, "\"two words\"");
        assert_eq!(read[4].raw, r"C:\keys\\x");
        assert!(tokens("\"open").is_err());
        assert_eq!(
            directive("\tAuthorizedKeysFile=a b"),
            ("AuthorizedKeysFile", "a b")
        );
        assert_eq!(directive("\"Match\" all"), ("Match", "all"));
        Ok(())
    }

    #[test]
    fn a_block_goes_after_global_settings_and_comes_out_exactly() -> Result<()> {
        let block = render("aa", "someone", 22, &keys(&["a", "/b c/d"]), "\r\n");
        // Latin-1 in a comment and CRLF.
        for (original, before) in [
            (&b"# caf\xe9\r\nPort 22\r\n"[..], None),
            (
                b"Port 22\r\n  match Group x\r\n  Banner none\r\n",
                Some("  match"),
            ),
        ] {
            let updated = insert(original, &block)?;
            let found = blocks(&updated)?;
            assert_eq!(found.len(), 1);
            assert_eq!(
                found[0].managed,
                Some(Managed {
                    user: "someone".into(),
                    port: 22,
                    keys: keys(&["a", "/b c/d"]),
                })
            );
            if let Some(next) = before {
                assert!(updated[found[0].span.end..].starts_with(next.as_bytes()));
            }
            assert_eq!(
                splice(&updated, &[(found[0].span.clone(), String::new())]),
                original
            );
            // A second profile goes ahead of the first, never inside it.
            let second = render("bb", "someone", 22, &keys(&["a"]), "\r\n");
            let both = insert(&updated, &second)?;
            let found = blocks(&both)?;
            assert_eq!(found.len(), 2);
            assert_eq!(found[0].id, "bb");
            assert!(found.iter().all(|block| block.managed.is_some()));
        }
        let unterminated = insert(b"Port 22", &render("aa", "a", 1, &keys(&["k"]), "\n"))?;
        assert!(unterminated.starts_with(b"Port 22\n# BEGIN"));
        Ok(())
    }

    #[test]
    fn an_edited_or_unclear_block_is_not_treated_as_owned() -> Result<()> {
        let block = render("aa", "someone", 22, &keys(&["k"]), "\n");
        let edited = block.replace("Match all", "Banner none\nMatch all");
        assert!(blocks(edited.as_bytes())?[0].managed.is_none());
        let widened = block.replace("Address 127.0.0.1 Local", "Address * Local");
        assert!(blocks(widened.as_bytes())?[0].managed.is_none());
        let open = block.replace(&format!("{END}aa\n"), "");
        assert!(blocks(open.as_bytes()).is_err());
        assert!(blocks(format!("{block}{block}").as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn include_names_match_as_glob_does() {
        assert!(matches("*.conf", "10-a.conf"));
        assert!(matches("*", "100-macos"));
        assert!(matches("??-*.conf", "10-a.conf"));
        assert!(!matches("*.conf", "a.conf.bak"));
        assert!(!matches("*", ".hidden"));
    }
}
