/** The coffee honor flow: open the link, then ask whether the payment went through. */
import { h } from "./dom.js";
import { call, openUrl } from "./api.js";
import { S, btn, errText, toast } from "./view.js";
import type { Coffee } from "./types.js";

/** Open the donation link and show the dialog. Resolve true when the user marks the year as paid. */
export async function buyCoffee(): Promise<boolean> {
  try {
    const info = (await call({ type: "coffee_status" })) as unknown as Coffee;
    await openUrl(info.link);
  } catch (e) {
    toast("bad", "LINK NOT OPENED", errText(e));
  }
  return new Promise<boolean>((resolve) => {
    const dlg = h("dialog", { class: "coffee-dlg", "aria-labelledby": "coffee-dlg-t" });
    const err = h("div", { class: "err", role: "alert" });
    const close = (paid: boolean) => {
      dlg.close();
      dlg.remove();
      resolve(paid);
    };
    const yes = btn("Yes, it went through", async () => {
      try {
        S.coffee = (await call({ type: "coffee_mark_paid" })) as unknown as Coffee;
        toast("ok", "COFFEE", "Thank you for the coffee.");
        close(true);
      } catch (e) {
        err.textContent = errText(e);
      }
    });
    dlg.addEventListener("cancel", () => close(false));
    dlg.append(
      h("h2", { id: "coffee-dlg-t", class: "disp mid" }, "Did it go through?"),
      h("p", {}, "Warden can't see your payment, so I'll just trust you on this one :)"),
      h("div", { class: "foot" }, yes, btn("Not yet", () => close(false))),
      err,
    );
    document.body.append(dlg);
    dlg.showModal();
  });
}
