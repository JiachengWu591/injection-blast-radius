// Parse every ```mermaid block with mermaid itself.
//
// The companion to tools/check_mermaid.py. That one is pure Python, runs inside
// `python verify.py`, and finds constructs GitHub's renderer mishandles — but
// it cannot tell you whether a diagram parses, because only mermaid knows its
// own grammar. This does, at the cost of needing node:
//
//     npm install mermaid@11 jsdom
//     node tools/check_mermaid.mjs ARCHITECTURE.md ARCHITECTURE.zh-CN.md
//
// Deliberately not wired into verify.py: that command's promise is one step
// with no extra toolchain, and a node dependency would end it. Run this when
// you change a diagram.
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

// mermaid reaches for a DOM even to parse — DOMPurify installs hooks at import.
const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  pretendToBeVisual: true,
});
globalThis.window = dom.window;
globalThis.document = dom.window.document;
// node 24 makes `navigator` a getter-only global, so plain assignment throws.
Object.defineProperty(globalThis, "navigator", {
  value: dom.window.navigator,
  configurable: true,
});
for (const name of [
  "Node",
  "Element",
  "HTMLElement",
  "DocumentFragment",
  "SVGElement",
  "NodeFilter",
  "DOMParser",
  "XMLSerializer",
  "getComputedStyle",
]) {
  globalThis[name] = dom.window[name];
}
globalThis.requestAnimationFrame = (cb) => setTimeout(cb, 0);

const mermaid = (await import("mermaid")).default;
// The configuration GitHub uses, so a diagram that passes here is one GitHub
// can render rather than one that merely parses somewhere.
mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: node tools/check_mermaid.mjs <file.md> [...]");
  process.exit(2);
}

let failures = 0;
let checked = 0;

for (const file of files) {
  const blocks = [
    ...readFileSync(file, "utf8").matchAll(/```mermaid\n([\s\S]*?)```/g),
  ].map((m) => m[1]);
  console.log(`\n${file} — ${blocks.length} block(s)`);
  for (let i = 0; i < blocks.length; i++) {
    const kind = blocks[i].trim().split("\n")[0].trim();
    checked++;
    try {
      await mermaid.parse(blocks[i]);
      console.log(`  [${i + 1}] ok      ${kind}`);
    } catch (err) {
      failures++;
      console.log(`  [${i + 1}] FAILED  ${kind}`);
      const message = err && err.message ? err.message : String(err);
      console.log(
        message
          .split("\n")
          .slice(0, 14)
          .map((line) => "          " + line)
          .join("\n"),
      );
    }
  }
}

console.log(
  `\n${checked - failures}/${checked} block(s) parse under mermaid ` +
    `${mermaid.version ?? "(version unknown)"}`,
);
process.exit(failures ? 1 : 0);
