// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.
//
// NOTE: the Radii name, mark and wordmark are trademarks of the original
// author and are NOT covered by the licence above — see the Trademark Notice
// in the root README. The code in this file is AGPL; the artwork it embeds
// from assets/brand/ is not.

//! The CLI's brand surface: the mark, the palette, and the rules deciding
//! which of them a given terminal is allowed to see.

use std::io::IsTerminal;

/// The mark on a 28x14 character grid, drawn in braille. A braille cell is a
/// 2x4 dot matrix and a terminal cell is roughly 1 wide by 2 tall, so those
/// dots come out square — 8x the resolution of one character, which is what a
/// tone ramp at this size cannot give you.
pub const MARK_BRAILLE: &str = include_str!("../../../assets/brand/ascii/mark-braille.txt");

/// The same raster on the same grid through a luminance ramp, for anything
/// that cannot be trusted with Unicode at all. Both come out of
/// `scripts/gen-ascii-mark.py`; edit that, never these files.
pub const MARK_ASCII: &str = include_str!("../../../assets/brand/ascii/mark-ascii.txt");

pub const TAGLINE: &str = "a runtime for header-less content delivery";

/// Reach — primary, and *reachable* in a route table. The same colour means the
/// same thing in the mark and in the data.
pub const REACH: anstyle::RgbColor = anstyle::RgbColor(0x16, 0xC7, 0x9A);
/// Severed — a path that is down.
pub const SEVERED: anstyle::RgbColor = anstyle::RgbColor(0xF2, 0x67, 0x4A);
/// Unknown — unprobed or stale.
pub const UNKNOWN: anstyle::RgbColor = anstyle::RgbColor(0x7C, 0x8B, 0x93);

/// Which cut of the mark, if any, this terminal gets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cut {
    Braille,
    Ascii,
    None,
}

/// Everything about the environment that changes what we print, resolved once
/// so the decision is a pure function over it and can be tested without
/// touching process state.
#[derive(Clone, Debug, Default)]
pub struct Term {
    pub stdout_is_tty: bool,
    pub no_color: bool,
    pub term: Option<String>,
    pub term_program: Option<String>,
    pub wt_session: bool,
    /// The first of `LC_ALL`, `LC_CTYPE`, `LANG` that is set.
    pub locale: Option<String>,
    /// `RADII_BANNER=braille|ascii|none` — an escape hatch for when detection
    /// is wrong, which for braille it sometimes will be.
    pub banner_override: Option<String>,
}

impl Term {
    pub fn detect() -> Self {
        Self {
            stdout_is_tty: std::io::stdout().is_terminal(),
            // Per the NO_COLOR convention: any value, including empty, disables.
            no_color: std::env::var_os("NO_COLOR").is_some(),
            term: std::env::var("TERM").ok(),
            term_program: std::env::var("TERM_PROGRAM").ok(),
            wt_session: std::env::var_os("WT_SESSION").is_some(),
            locale: ["LC_ALL", "LC_CTYPE", "LANG"]
                .iter()
                .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty())),
            banner_override: std::env::var("RADII_BANNER").ok(),
        }
    }

    fn term_is_dumb(&self) -> bool {
        matches!(self.term.as_deref(), Some("dumb") | Some(""))
    }

    /// A UTF-8 locale does not promise the font actually has the braille block,
    /// so this is a best guess rather than a guarantee — hence the override.
    fn unicode_is_safe(&self) -> bool {
        if self.wt_session || self.term_program.is_some() {
            return true;
        }
        match self.locale.as_deref() {
            Some(l) => {
                let l = l.to_ascii_lowercase();
                l.contains("utf-8") || l.contains("utf8")
            }
            None => false,
        }
    }

    pub fn cut(&self) -> Cut {
        match self.banner_override.as_deref() {
            Some("braille") => return Cut::Braille,
            Some("ascii") => return Cut::Ascii,
            Some("none") => return Cut::None,
            _ => {}
        }
        // A banner in a log file is litter, so anything that is not a terminal
        // a human is looking at gets nothing.
        if !self.stdout_is_tty || self.term_is_dumb() {
            return Cut::None;
        }
        if self.unicode_is_safe() {
            Cut::Braille
        } else {
            Cut::Ascii
        }
    }

    pub fn color(&self) -> bool {
        self.stdout_is_tty && !self.no_color && !self.term_is_dumb()
    }
}

fn tint(text: &str, color: anstyle::RgbColor, on: bool) -> String {
    if !on {
        return text.to_string();
    }
    let style = anstyle::Style::new().fg_color(Some(anstyle::Color::Rgb(color)));
    format!("{style}{text}{style:#}")
}

/// Characters of the bottom row that are hub rather than baseline. The hub sits
/// at x=10 in a 50.9-unit-wide crop over 28 columns, so it lands in the first
/// two cells of either cut.
const HUB_CELLS: usize = 2;

/// Lays the wordmark alongside the mark, vertically centred against it.
///
/// The hub is the only part of the mark that carries colour. Neither cut can
/// separate it from the baseline it sits on — they share cells — so the tint
/// goes on the cells the hub occupies, which is an approximation the vector
/// master does not have to make.
fn compose(mark: &str, version: &str, color: bool) -> String {
    let lines: Vec<&str> = mark.lines().collect();
    let width = lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or_default();
    let text_at = lines.len().saturating_sub(1) / 2;
    let name = format!("radii {version}");

    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let columns = line.chars().count();
        let drawn = if i == lines.len() - 1 && columns > HUB_CELLS {
            let split = line
                .char_indices()
                .nth(HUB_CELLS)
                .map(|(n, _)| n)
                .unwrap_or(line.len());
            format!("{}{}", tint(&line[..split], REACH, color), &line[split..])
        } else {
            (*line).to_string()
        };
        out.push_str(&drawn);
        // Pad against the line's character count, not the drawn string's byte
        // length: a tint adds bytes that occupy no columns.
        if i == text_at {
            out.push_str(&" ".repeat(width.saturating_sub(columns) + 4));
            out.push_str(&name);
        } else if i == text_at + 1 {
            out.push_str(&" ".repeat(width.saturating_sub(columns) + 4));
            out.push_str(&tint(TAGLINE, UNKNOWN, color));
        }
        out.push('\n');
    }
    // No trailing blank line: clap spaces the sections itself.
    out.truncate(out.trim_end().len());
    out
}

/// The banner for bare `--help`. `None` when this terminal gets no art.
pub fn banner(term: &Term, version: &str) -> Option<String> {
    let color = term.color();
    match term.cut() {
        Cut::Braille => Some(compose(MARK_BRAILLE, version, color)),
        Cut::Ascii => Some(compose(MARK_ASCII, version, color)),
        Cut::None => None,
    }
}

/// How a command should render its result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// `--json`: one JSON document, for anything parsing us on purpose.
    Json,
    /// Piped without `--json`: stable `key=value` lines. Scripts already
    /// depend on these, so they never change shape for cosmetic reasons.
    Plain,
    /// A terminal a human is reading: aligned columns, glyphs, colour.
    Pretty,
}

pub fn format(term: &Term, json: bool) -> Format {
    if json {
        Format::Json
    } else if term.stdout_is_tty {
        Format::Pretty
    } else {
        Format::Plain
    }
}

/// The glyph for a reachability state, in the colour that state always takes.
///
/// `None` is *unprobed* — a node the graph knows of but holds no observation
/// for, which is a different thing from one observed to be unreachable.
pub fn reach_glyph(reachable: Option<bool>, term: &Term) -> String {
    match reachable {
        Some(true) => tinted("\u{25cf}", REACH, term),
        Some(false) => tinted("\u{25d0}", SEVERED, term),
        None => tinted("\u{25cb}", UNKNOWN, term),
    }
}

/// Dim text — units, absent values, anything the eye should skip.
pub fn dim(text: &str, term: &Term) -> String {
    tinted(text, UNKNOWN, term)
}

/// A section heading, matching clap's own help headings.
pub fn heading(text: &str, term: &Term) -> String {
    if !term.color() {
        return text.to_string();
    }
    let style = anstyle::Style::new()
        .bold()
        .fg_color(Some(anstyle::Color::Rgb(UNKNOWN)));
    format!("{style}{text}{style:#}")
}

/// A literal the user types — a command or a flag — matching clap's own.
pub fn literal(text: &str, term: &Term) -> String {
    if !term.color() {
        return text.to_string();
    }
    let style = anstyle::Style::new().bold();
    format!("{style}{text}{style:#}")
}

/// One of the three reachability colours, applied only if this terminal gets
/// colour at all.
pub fn tinted(text: &str, color: anstyle::RgbColor, term: &Term) -> String {
    tint(text, color, term.color())
}

/// The reachability legend, in the three colours that mean the same three
/// things everywhere else in the system.
pub fn legend(term: &Term) -> String {
    let c = term.color();
    format!(
        "{} reachable   {} severed   {} unprobed",
        tint("\u{25cf}", REACH, c),
        tint("\u{25d0}", SEVERED, c),
        tint("\u{25cb}", UNKNOWN, c),
    )
}

/// clap's help colours, drawn from the same palette.
pub fn clap_styles() -> clap::builder::Styles {
    use anstyle::{Color, Style};
    clap::builder::Styles::styled()
        .header(Style::new().bold().fg_color(Some(Color::Rgb(UNKNOWN))))
        .usage(Style::new().bold().fg_color(Some(Color::Rgb(UNKNOWN))))
        .literal(Style::new().bold())
        .placeholder(Style::new().fg_color(Some(Color::Rgb(REACH))))
        .valid(Style::new().fg_color(Some(Color::Rgb(REACH))))
        .invalid(Style::new().fg_color(Some(Color::Rgb(SEVERED))))
        .error(Style::new().bold().fg_color(Some(Color::Rgb(SEVERED))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tty() -> Term {
        Term {
            stdout_is_tty: true,
            ..Term::default()
        }
    }

    #[test]
    fn a_pipe_gets_no_art_and_no_colour() {
        let piped = Term::default();
        assert_eq!(piped.cut(), Cut::None);
        assert!(!piped.color());
        assert!(banner(&piped, "0.1.0").is_none());
    }

    #[test]
    fn a_dumb_terminal_gets_no_art() {
        let t = Term {
            term: Some("dumb".into()),
            ..tty()
        };
        assert_eq!(t.cut(), Cut::None);
        assert!(!t.color());
    }

    #[test]
    fn a_legacy_locale_falls_back_to_the_ascii_ramp() {
        for locale in [None, Some("C".to_string()), Some("en_US.ISO-8859-1".into())] {
            let t = Term {
                locale,
                term: Some("xterm-256color".into()),
                ..tty()
            };
            assert_eq!(t.cut(), Cut::Ascii, "{t:?}");
        }
    }

    #[test]
    fn a_utf8_locale_or_a_known_emulator_gets_the_braille_cut() {
        for t in [
            Term {
                locale: Some("en_US.UTF-8".into()),
                ..tty()
            },
            Term {
                wt_session: true,
                ..tty()
            },
            Term {
                term_program: Some("iTerm.app".into()),
                ..tty()
            },
        ] {
            assert_eq!(t.cut(), Cut::Braille, "{t:?}");
        }
    }

    #[test]
    fn the_override_wins_over_detection() {
        let t = Term {
            banner_override: Some("braille".into()),
            ..Term::default()
        };
        assert_eq!(t.cut(), Cut::Braille);

        let t = Term {
            banner_override: Some("none".into()),
            wt_session: true,
            ..tty()
        };
        assert_eq!(t.cut(), Cut::None);
    }

    #[test]
    fn no_color_keeps_the_art_but_drops_the_tint() {
        let t = Term {
            no_color: true,
            wt_session: true,
            ..tty()
        };
        assert_eq!(t.cut(), Cut::Braille);
        assert!(!t.color());
        let banner = banner(&t, "0.1.0").unwrap();
        assert!(
            !banner.contains('\u{1b}'),
            "no escape sequences without colour"
        );
    }

    #[test]
    fn the_banner_carries_the_name_and_tagline() {
        let t = Term {
            wt_session: true,
            no_color: true,
            ..tty()
        };
        let banner = banner(&t, "9.9.9").unwrap();
        assert!(banner.contains("radii 9.9.9"));
        assert!(banner.contains(TAGLINE));
        assert_eq!(banner.lines().count(), MARK_BRAILLE.lines().count());
    }

    #[test]
    fn tinting_the_hub_does_not_shift_the_wordmark() {
        let plain = Term {
            wt_session: true,
            no_color: true,
            ..tty()
        };
        let tinted = Term {
            wt_session: true,
            ..tty()
        };
        let strip = |s: String| {
            s.lines()
                .map(|l| {
                    l.chars()
                        .scan(false, |esc, c| {
                            if c == '\u{1b}' {
                                *esc = true;
                            } else if *esc && c == 'm' {
                                *esc = false;
                                return Some(None);
                            }
                            Some(if *esc { None } else { Some(c) })
                        })
                        .flatten()
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            strip(banner(&plain, "0.1.0").unwrap()),
            strip(banner(&tinted, "0.1.0").unwrap())
        );
    }

    #[test]
    fn both_cuts_are_the_same_grid() {
        let braille: Vec<&str> = MARK_BRAILLE.lines().collect();
        let ascii: Vec<&str> = MARK_ASCII.lines().collect();
        assert_eq!(braille.len(), 14);
        assert_eq!(ascii.len(), 14);
        assert!(braille.iter().all(|l| l.chars().count() <= 28));
        assert!(ascii.iter().all(|l| l.chars().count() <= 28));
        // The ASCII cut has to survive a byte-oriented terminal.
        assert!(MARK_ASCII.is_ascii(), "the ascii cut must be ascii");
    }
}
