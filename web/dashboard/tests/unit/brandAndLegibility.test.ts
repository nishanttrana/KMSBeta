import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { C } from "../../src/components/v3/theme";

const ROOT = join(__dirname, "..", "..");

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== "generated") sources(path, out);
    } else if (/\.(tsx?|css)$/.test(name)) {
      out.push(path);
    }
  }
  return out;
}

const FILES = sources(join(ROOT, "src"));

function offenders(pattern: RegExp): string[] {
  const hits: string[] = [];
  for (const file of FILES) {
    readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      if (pattern.test(line)) hits.push(`${file.slice(ROOT.length + 1)}:${i + 1}`);
    });
  }
  return hits;
}

function inFiles(pattern: RegExp): string[] {
  const hits: string[] = [];
  for (const file of FILES) {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(pattern)) hits.push(`${file.slice(ROOT.length + 1)}:${text.slice(0, m.index).split("\n").length}`);
  }
  return hits;
}

describe("dashboard legibility and brand", () => {
  it("has no text smaller than 10px", () => {
    expect(offenders(/fontSize:\s*"?[0-9](\.\d+)?(px)?"?\s*[,}]|fontSize=\{[0-9](\.\d+)?\}|text-\[[0-9](\.\d+)?px\]|font-size:\s*[0-9](\.\d+)?px/)).toEqual([]);
  });

  // C.green and the other hex hues don't change with the theme; as text they
  // fail contrast on the light theme. Text takes the *Fg token.
  it("colours text with theme-reactive tokens", () => {
    const hue = "accent|teal|green|red|amber|orange|purple|blue|pink|cyan|yellow";
    const inStyle = new RegExp(`style=\\{\\{(?:(?!\\}\\}).)*?(?<!\\w)color:\\s*[^,}\`$]*\\bC\\.(${hue})\\b(?![A-Za-z0-9])`);
    expect(offenders(inStyle)).toEqual([]);
  });

  // Same rule for a style object that spans lines.
  it("colours text with theme-reactive tokens in multi-line styles", () => {
    const hue = "accent|teal|green|red|amber|orange|purple|blue|pink|cyan|yellow";
    expect(inFiles(new RegExp(`style=\\{\\{(?:(?!\\}\\})[\\s\\S])*?(?<!\\w)color:\\s*[^,}\`$]*\\bC\\.(${hue})\\b(?![A-Za-z0-9])`, "g"))).toEqual([]);
  });

  // Most tab files are @ts-nocheck, so a misspelt palette key compiles and
  // renders as "undefined": no border, no divider, an inherited colour.
  it("uses only palette keys that exist", () => {
    const missing = new Set<string>();
    for (const file of FILES) {
      if (file.endsWith("theme.ts")) continue;
      for (const m of readFileSync(file, "utf8").matchAll(/(?<![\w.])C\.([A-Za-z][A-Za-z0-9]*)\b/g)) {
        if (!(m[1]! in C)) missing.add(`${file.slice(ROOT.length + 1)}: C.${m[1]}`);
      }
    }
    expect([...missing]).toEqual([]);
  });

  // Pages lead with numbers and charts (CLAUDE.md). A text-only element
  // holding a paragraph folds to one line (.vk-fold) unless it is a warning
  // or confirmation that must stay open (data-keep).
  it("folds paragraphs of explanation", () => {
    expect(inFiles(/<(div|p|span)\b(?![^<>]*(?:vk-fold|data-keep))[^<>]*>\s*[A-Z][^<>{}=;]{120,}?\s*<\/\1>/g)).toEqual([]);
  });

  // The hex hues are fixed for both themes, and reach text and fills through
  // props the style gates cannot follow. Each must read on both cards.
  it("picks hex hues that read on the light and the dark card", () => {
    const lum = (hex: string) => {
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
    };
    const contrast = (a: string, b: string) => { const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x); return (hi! + 0.05) / (lo! + 0.05); };
    const css = readFileSync(join(ROOT, "src/index.css"), "utf8");
    const card = (theme: string) => (css.slice(css.indexOf(`[data-theme="${theme}"]`)).match(/--c-card:\s*(#[0-9a-f]{6})/) ?? [])[1]!;
    for (const hue of ["accent", "teal", "green", "red", "amber", "orange", "purple", "blue", "pink", "cyan", "yellow"] as const) {
      expect(contrast(C[hue], card("light")), `${hue} on the light card`).toBeGreaterThanOrEqual(3);
      expect(contrast(C[hue], card("dark")), `${hue} on the dark card`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("loads no font or stylesheet from another host", () => {
    expect(offenders(/@import\s+url\(|fonts\.googleapis|fonts\.gstatic/)).toEqual([]);
  });

  it("has no inline script in index.html, which the console's CSP would refuse", () => {
    const html = readFileSync(join(ROOT, "index.html"), "utf8");
    expect(html.match(/<script(?![^>]*\bsrc=)[^>]*>/g) ?? []).toEqual([]);
  });

  it("draws the same mark in the app, the first-paint splash and the favicon", () => {
    const v = (s: string) => (s.match(/d="(M[^"]+)"/) ?? [])[1];
    const mark = readFileSync(join(ROOT, "src/components/BrandMark.tsx"), "utf8");
    const html = readFileSync(join(ROOT, "index.html"), "utf8");
    expect(v(mark)).toBeTruthy();
    expect(v(html)).toBe(v(mark));
    const core = (s: string) => (s.match(/vk-mark-core" d="(M[^"]+)"/) ?? [])[1];
    expect(core(mark)).toBeTruthy();
    expect(core(html)).toBe(core(mark));
    expect((readFileSync(join(ROOT, "public/favicon.svg"), "utf8").match(/<path /g) ?? []).length).toBe(2);
  });
});
