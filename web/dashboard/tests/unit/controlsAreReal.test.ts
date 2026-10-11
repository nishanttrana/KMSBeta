import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// A control on a page does something (CLAUDE.md rule 8). The create-key
// dialog had a one-option Tenant selector and four fields keycore was never
// sent; two enrollment wizards read a selector's choice from a button that
// has no value, so the choice was always the default (11.6.0-beta).

const ROOT = join(__dirname, "..", "..");

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (name.endsWith(".tsx")) out.push(path);
  }
  return out;
}

// Every opening tag of the named elements, with its attributes.
function tags(text: string, names: string): { line: number; tag: string }[] {
  const out: { line: number; tag: string }[] = [];
  for (const m of text.matchAll(new RegExp(`<(${names})\\b`, "g"))) {
    let depth = 0, quote = "", end = m.index + m[0].length;
    for (; end < text.length; end++) {
      const c = text[end]!;
      if (quote) { if (c === quote) quote = ""; }
      else if (depth === 0 && (c === '"' || c === "'")) quote = c;
      else if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (c === ">" && depth === 0) break;
    }
    out.push({ line: text.slice(0, m.index).split("\n").length, tag: text.slice(m.index, end + 1) });
  }
  return out;
}

function without(names: string, wired: RegExp): string[] {
  const hits: string[] = [];
  for (const file of sources(join(ROOT, "src"))) {
    for (const { line, tag } of tags(readFileSync(file, "utf8"), names)) {
      if (!wired.test(tag) && !tag.includes("{...")) hits.push(`${file.slice(ROOT.length + 1)}:${line}`);
    }
  }
  return hits;
}

describe("controls change something", () => {
  // The shared Sel is a button and a listbox: it has no value to read by id.
  it("every selector has a change handler", () => {
    expect(without("Sel|select", /\bonChange\b/)).toEqual([]);
  });

  // A box that is always ticked is a claim, not a control; one that only
  // shows a fixed state says so with disabled.
  it("every checkbox and radio has a handler, or is disabled", () => {
    expect(without("Chk|Radio", /\b(onChange|onSelect|onChecked|onClick|disabled)\b/)).toEqual([]);
    const boxes: string[] = [];
    for (const file of sources(join(ROOT, "src"))) {
      for (const { line, tag } of tags(readFileSync(file, "utf8"), "input")) {
        if (/type="(checkbox|radio)"/.test(tag) && !/\b(onChange|onClick|disabled|readOnly)\b|\{\.\.\./.test(tag)) boxes.push(`${file.slice(ROOT.length + 1)}:${line}`);
      }
    }
    expect(boxes).toEqual([]);
  });

  // A text field is held in state, or is a native input read by its id.
  it("every text field is read", () => {
    expect(without("Inp|Txt|input|textarea", /\b(onChange|onInput|ref|readOnly|id)\b|type="hidden"/)).toEqual([]);
  });

  it("reads no selector by id", () => {
    const hits: string[] = [];
    for (const file of sources(join(ROOT, "src"))) {
      const text = readFileSync(file, "utf8");
      const ids = new Set(tags(text, "Sel").map(({ tag }) => (tag.match(/\bid="([^"]+)"/) ?? [])[1]).filter(Boolean));
      for (const m of text.matchAll(/getElementById\("([^"]+)"\)/g)) if (ids.has(m[1])) hits.push(`${file.slice(ROOT.length + 1)}: ${m[1]}`);
    }
    expect(hits).toEqual([]);
  });
});
