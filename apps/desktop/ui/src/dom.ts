/** Tiny DOM helpers. Text always goes in as text nodes, never as HTML. */

export type Child = Node | string | number | null | undefined | false;
type Props = Record<string, unknown>;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props?: Props | null,
  ...kids: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = String(v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
    else if (k in el && k !== "list") (el as unknown as Props)[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, kids);
  return el;
}

export function append(el: Element, kids: Child[]): void {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

/** Parse a static SVG constant. Never pass data to this function. */
export function svg(markup: string): Element {
  const t = document.createElement("template");
  t.innerHTML = markup;
  return t.content.firstElementChild as Element;
}

export function replace(el: Element, ...kids: Child[]): void {
  el.replaceChildren();
  append(el, kids);
}
