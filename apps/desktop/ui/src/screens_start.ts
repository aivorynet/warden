/** First-run and gate screens: pledge, unlock, create vault, Emergency Kit, daemon down. */
import { h, replace } from "./dom.js";
import { call, initVault, openUrl, signPledge, startService } from "./api.js";
import { S, cta, btn, errText, field, mug, simpleBar, toast, eyebrow, lockup } from "./view.js";
import type { Kit } from "./types.js";

const SOURCE = "https://github.com/aivorynet/warden";
const PLEDGE_TEXT =
  "I promise: if Warden saves me from one expired token, Paul gets his coffee. A promise is a promise, even on the internet.";

export function pledge(root: HTMLElement): void {
  const info = S.coffee;
  const device = S.app?.status ? S.app.status.device_id.slice(-8).toUpperCase() : "THIS DEVICE";
  const signed = h("span", {});
  const err = h("div", { class: "err", role: "alert" });
  const go = cta(
    "Deal. Let's go",
    async () => {
      try {
        await signPledge();
        await S.refresh();
        S.go(S.app?.vault_exists ? "unlock" : "init");
      } catch (e) {
        err.textContent = errText(e);
      }
    },
    { disabled: true, large: true },
  );
  const box = h("input", {
    type: "checkbox",
    onchange: () => {
      go.disabled = !box.checked;
      const d = new Date();
      const p = (n: number) => String(n).padStart(2, "0");
      signed.textContent = box.checked ? `you · ${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}` : "";
    },
  });
  replace(
    root,
    simpleBar(h("span", { class: "meta-top" }, "BEFORE WE TAKE THE KEYS")),
    h(
      "div",
      { class: "pledge" },
      h(
        "main",
        {},
        h("h1", { class: "disp" }, "Free to rotate."),
        h("span", { class: "tag" }, "ONE COFFEE A YEAR."),
        h("p", {}, "Hi, Paul here. I built Warden because expired tokens kept breaking my deploys at the worst time. So go ahead and use it. Free and open source. Every feature, no trial, no locked buttons."),
        h("p", {}, "The catch: you promise me a coffee once a year, when Warden saves you from your first expired token. Pay what you want. I will remind you after your first rotation and then once a week. Politely."),
        h("p", {}, "If Warden never saves you a minute, you owe me nothing."),
        h("div", { class: "foot" }, go, h("a", { href: SOURCE, onclick: (e: Event) => { e.preventDefault(); void openUrl(SOURCE); } }, "Read the source first")),
        err,
      ),
      h(
        "aside",
        {},
        h("div", { class: "stripe", "aria-hidden": "true" }),
        h(
          "div",
          { class: "ticket" },
          h("div", { class: "hd" }, h("b", {}, "KEY TICKET"), h("span", {}, `NO. ${info?.ticket || "AIVW-2026-0000"}`)),
          h("div", { class: "tr" }, h("span", {}, "DEVICE"), h("b", {}, device)),
          h("div", { class: "tr" }, h("span", {}, "GUARDS"), h("span", { class: "sans" }, "admin tokens, API keys, .env files")),
          h("div", { class: "tr" }, h("span", {}, "CHARGE NOW"), h("span", { class: "zero" }, "0.00")),
          h("div", { class: "perf", "aria-hidden": "true" }),
          h("div", { class: "cp" }, h("span", {}, "COFFEE COUPON · ONCE A YEAR"), mug()),
          h("label", {}, box, h("span", {}, PLEDGE_TEXT)),
          h("span", { class: "price" }, "PAY WHAT YOU WANT · €5 SUGGESTED"),
          h("div", { class: "sign" }, h("span", {}, "SIGNED"), signed),
        ),
        h("p", {}, "No account, no trial. Warden checks a signed receipt offline, and it never stops a rotation. Open source under the MIT licence."),
      ),
    ),
  );
}

export function kitCard(kit: Kit, done?: () => void): HTMLElement {
  return h(
    "aside",
    { class: "kit", "aria-label": "Emergency Kit" },
    h("div", { class: "hd" }, h("h2", {}, "Emergency Kit"), h("span", { class: "mono steel small" }, "FIRST RUN")),
    h("p", { class: "lead small" }, "Print this page or keep it offline. Without it a lost password means a lost vault."),
    h("div", { class: "sk" }, h("span", { class: "k" }, "SECRET KEY"), h("span", { class: "v" }, kit.secret_key)),
    h("div", { class: "f" }, h("span", { class: "k" }, "MASTER PASSWORD"), h("span", { class: "blank" })),
    h("div", { class: "f" }, h("span", { class: "k" }, "VAULT ID"), h("span", { class: "v" }, kit.vault)),
    h("div", { class: "btns" }, btn("Save as PDF", () => window.print(), "solid"), btn("I stored it", () => done?.())),
  );
}

function unlockForm(): HTMLElement {
  const pw = h("input", { type: "password", autocomplete: "current-password", required: true });
  const sk = h("input", { class: "mono", spellcheck: false, autocomplete: "off", required: true });
  const stay = h("input", { type: "checkbox", checked: true });
  const err = h("div", { class: "err", role: "alert" });
  return h(
    "form",
    {
      onsubmit: async (e: Event) => {
        e.preventDefault();
        err.textContent = "";
        try {
          await call({ type: "unlock", password: pw.value, secret_key: sk.value.trim() });
          pw.value = "";
          sk.value = "";
          const cur = await call({ type: "get_settings" });
          if (cur["keychain_cache"] !== stay.checked) await call({ type: "set_settings", settings: { default_interval: cur["default_interval"], coffee_reminder: cur["coffee_reminder"], keychain_cache: stay.checked } });
          await S.refresh();
          S.go("tokens");
        } catch (ex) {
          err.textContent = errText(ex);
        }
      },
    },
    eyebrow("VAULT · THIS DEVICE"),
    h("h1", { class: "disp" }, "Unlock"),
    h("p", { class: "lead" }, "Your password and your Secret Key open the vault. Nobody else has them, Aivory too."),
    h("div", { class: "bar" }),
    field("MASTER PASSWORD", pw, "lg"),
    field("SECRET KEY", sk, "lg"),
    h("label", { class: "check" }, stay, "Stay unlocked for background rotation"),
    cta("Unlock", () => {}, { type: "submit" }),
    err,
  );
}

export function unlock(root: HTMLElement, sample?: Kit): void {
  replace(root, simpleBar(null), h("div", { class: "pair" }, unlockForm(), sample ? kitCard(sample) : null));
}

export function init(root: HTMLElement): void {
  const device = h("input", { value: "", placeholder: "this computer" });
  const pw = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 8 });
  const again = h("input", { type: "password", autocomplete: "new-password", required: true });
  const err = h("div", { class: "err", role: "alert" });
  const submit = cta("Create vault", () => {}, { type: "submit" });
  replace(
    root,
    simpleBar(null),
    h(
      "div",
      { class: "pair" },
      h(
        "form",
        {
          onsubmit: async (e: Event) => {
            e.preventDefault();
            err.textContent = "";
            if (pw.value !== again.value) return void (err.textContent = "The two passwords differ.");
            if (pw.value.length < 8) return void (err.textContent = "The password needs at least 8 characters.");
            submit.disabled = true;
            try {
              S.kit = await initVault(pw.value, device.value);
              pw.value = again.value = "";
              await S.refresh();
              S.go("kit");
            } catch (ex) {
              err.textContent = errText(ex);
              submit.disabled = false;
            }
          },
        },
        eyebrow("NEW VAULT · THIS DEVICE"),
        h("h1", { class: "disp" }, "Create your vault"),
        h("p", { class: "lead" }, "Choose a master password. Warden makes a Secret Key and shows it once, in the Emergency Kit."),
        h("div", { class: "bar" }),
        field("DEVICE NAME", device, "lg"),
        field("MASTER PASSWORD", pw, "lg"),
        field("REPEAT PASSWORD", again, "lg"),
        submit,
        err,
      ),
    ),
  );
}

export function kit(root: HTMLElement): void {
  const k = S.kit;
  if (!k) return S.go("tokens");
  replace(
    root,
    simpleBar(null),
    h(
      "div",
      { class: "pair" },
      h("form", { onsubmit: (e: Event) => e.preventDefault() }, eyebrow("VAULT CREATED"), h("h1", { class: "disp" }, "Keep your key"), h("p", { class: "lead" }, "The vault is ready and unlocked. Store the Secret Key now. Warden cannot show it again."), h("div", { class: "bar" })),
      kitCard(k, () => {
        S.kit = null;
        S.go("tokens");
      }),
    ),
  );
}

export function down(root: HTMLElement): void {
  const err = h("div", { class: "err", role: "alert" }, S.app?.error ?? "");
  const b = cta("Start background service", async () => {
    b.disabled = true;
    err.textContent = "";
    try {
      await startService();
      toast("ok", "STARTED", "The background service runs.");
      await S.refresh();
      S.go("tokens");
    } catch (e) {
      err.textContent = errText(e);
      b.disabled = false;
    }
  });
  replace(
    root,
    simpleBar(null),
    h(
      "div",
      { class: "center" },
      eyebrow("DAEMON · NOT RUNNING"),
      h("h1", { class: "disp" }, "Warden sleeps"),
      h("p", { class: "lead" }, "The app is a front end. The background service holds the vault and rotates your tokens. It does not run now."),
      h("div", { class: "bar" }),
      b,
      err,
      h("p", { class: "hint" }, "This runs: aivory-warden service install"),
    ),
  );
}
