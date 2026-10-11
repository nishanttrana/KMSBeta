import type { Locator } from "@playwright/test";

// Asks the browser what is drawn at the centre of every icon, button and input
// under root. A fault is one that some other control covers, or that spills
// out of root.
export function coveredControls(root: Locator): Promise<string[]> {
  return root.evaluate((el) => {
    const box = el.getBoundingClientRect();
    const faults: string[] = [];
    for (const node of Array.from(el.querySelectorAll("svg, button, input"))) {
      const r = node.getBoundingClientRect();
      const name = `${node.tagName} "${node.getAttribute("title") || node.getAttribute("aria-label") || node.getAttribute("class") || ""}"`;
      if (!r.width || !r.height) { faults.push(`${name} has no size`); continue; }
      if (r.left < box.left - 0.5 || r.right > box.right + 0.5) faults.push(`${name} spills out of its container`);
      const x = r.left + r.width / 2, y = r.top + r.height / 2;
      // Scrolled out of a list: not on screen, so nothing can cover it.
      let clipped = false;
      for (let a = node.parentElement; a && a !== el.parentElement; a = a.parentElement) {
        const c = a.getBoundingClientRect();
        if (getComputedStyle(a).overflowY !== "visible" && (y < c.top || y > c.bottom)) clipped = true;
      }
      if (clipped) continue;
      // Below or above the window: the browser has nothing drawn there to ask
      // about. Scroll it into view and sweep again to check it.
      if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) continue;
      const hit = document.elementFromPoint(x, y);
      if (!hit || !(node.contains(hit) || hit.contains(node))) faults.push(`${name} is covered by ${hit?.tagName}`);
    }
    return faults;
  });
}
