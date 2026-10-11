import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

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
