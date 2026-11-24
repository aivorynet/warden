import { test } from "node:test";
import assert from "node:assert/strict";
import { originOf, selectionUrl } from "./host.js";

test("a selection in an iframe uses the frame origin", () => {
  const url = selectionUrl(
    { frameUrl: "https://evil.example.net/frame", pageUrl: "https://app.example.com/" },
    { url: "https://app.example.com/" },
  );
  assert.equal(originOf(url), "https://evil.example.net");
});

test("without a frame URL the tab URL is used", () => {
  assert.equal(selectionUrl({ pageUrl: "https://a.example.com/x" }, { url: "https://b.example.com/" }), "https://b.example.com/");
  assert.equal(selectionUrl({ pageUrl: "https://a.example.com/x" }, undefined), "https://a.example.com/x");
});
