//! The opencode theme. opencode 2.2.2 reads custom themes from
//! `<config dir>/themes/*.json` (packages/tui/src/theme/discovery.ts) and
//! selects one by `theme.name` in the TUI config, cli.json.

use std::fs;
use std::path::{Path, PathBuf};

/// The theme's name: its file name in `themes/` and `theme.name` in cli.json.
pub const THEME_NAME: &str = "nearai-red";
/// The shipped theme, relative to the plugin directory.
pub const THEME_FILE: &str = "branding/theme/nearai-red.json";

/// Copy the shipped theme into the session's isolated opencode config dir.
pub fn install(plugin_dir: &Path, config_dir: &Path) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let source = plugin_dir.join(THEME_FILE);
    let data = fs::read(&source).map_err(|e| format!("theme file missing: {} ({e}); reinstall rts", source.display()))?;
    // opencode would fall back to its default theme without a word.
    let doc: serde_json::Value = serde_json::from_slice(&data)
        .map_err(|e| format!("theme file {} is not JSON: {e}; reinstall rts", source.display()))?;
    if !doc["theme"].is_object() {
        return Err(format!("theme file {} has no theme object; reinstall rts", source.display()));
    }
    let dir = config_dir.join("themes");
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let file = dir.join(format!("{THEME_NAME}.json"));
    fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&file)
        .and_then(|mut f| f.write_all(&data))
        .map_err(|e| format!("writing {}: {e}", file.display()))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn shipped() -> (PathBuf, Value) {
        let plugin = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugin");
        let v = serde_json::from_str(&fs::read_to_string(plugin.join(THEME_FILE)).unwrap()).unwrap();
        (plugin, v)
    }

    /// The colour keys of opencode 2.2.2's v1 theme format
    /// (packages/tui/src/theme/assets/opencode.json at tag v2.2.2).
    const KEYS: [&str; 50] = [
        "primary", "secondary", "accent", "error", "warning", "success", "info", "text", "textMuted", "background",
        "backgroundPanel", "backgroundElement", "border", "borderActive", "borderSubtle", "diffAdded", "diffRemoved",
        "diffContext", "diffHunkHeader", "diffHighlightAdded", "diffHighlightRemoved", "diffAddedBg", "diffRemovedBg",
        "diffContextBg", "diffLineNumber", "diffAddedLineNumberBg", "diffRemovedLineNumberBg", "markdownText",
        "markdownHeading", "markdownLink", "markdownLinkText", "markdownCode", "markdownBlockQuote", "markdownEmph",
        "markdownStrong", "markdownHorizontalRule", "markdownListItem", "markdownListEnumeration", "markdownImage",
        "markdownImageText", "markdownCodeBlock", "syntaxComment", "syntaxKeyword", "syntaxFunction", "syntaxVariable",
        "syntaxString", "syntaxNumber", "syntaxType", "syntaxOperator", "syntaxPunctuation",
    ];

    #[test]
    fn the_shipped_theme_defines_every_colour_for_dark_and_light() {
        let (_, v) = shipped();
        assert_eq!(v["$schema"], "https://opencode.ai/theme.json");
        let defs = v["defs"].as_object().unwrap();
        let resolves = |s: &str| {
            s == "none"
                || (s.len() == 7 && s.starts_with('#') && s[1..].chars().all(|c| c.is_ascii_hexdigit()))
                || defs.get(s).and_then(Value::as_str).is_some_and(|h| h.starts_with('#'))
        };
        let theme = v["theme"].as_object().unwrap();
        assert_eq!(theme.len(), KEYS.len());
        for key in KEYS {
            for mode in ["dark", "light"] {
                let c = theme[key][mode].as_str().unwrap_or_else(|| panic!("{key}.{mode}"));
                assert!(resolves(c), "{key}.{mode} = {c}");
            }
        }
        // Red accent, pewter muted text, the terminal's own background.
        assert_eq!(defs["red"], "#EB1924");
        assert_eq!(theme["primary"]["dark"], "red");
        assert_eq!(theme["accent"]["light"], "red");
        assert_eq!(theme["textMuted"], serde_json::json!({ "dark": "pewter", "light": "pewter" }));
        assert_eq!(defs["pewter"], "#808088");
        assert_eq!(theme["background"]["dark"], "none");
        assert_eq!(defs["sand1"], "#A1977F");
    }

    #[test]
    fn install_copies_the_theme_privately_into_the_config_themes_dir() {
        use std::os::unix::fs::PermissionsExt;
        let (plugin, _) = shipped();
        let d = crate::testutil::tempdir("theme");
        let file = install(&plugin, &d.join("cfg")).unwrap();
        assert_eq!(file, d.join("cfg/themes/nearai-red.json"));
        assert_eq!(fs::read(&file).unwrap(), fs::read(plugin.join(THEME_FILE)).unwrap());
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        let e = install(&d.join("no-plugin"), &d.join("cfg")).unwrap_err();
        assert!(e.contains("branding/theme/nearai-red.json") && e.contains("reinstall"), "{e}");
        fs::create_dir_all(d.join("bad/branding/theme")).unwrap();
        fs::write(d.join("bad").join(THEME_FILE), "{").unwrap();
        assert!(install(&d.join("bad"), &d.join("cfg")).unwrap_err().contains("not JSON"));
        fs::remove_dir_all(d).unwrap();
    }
}
