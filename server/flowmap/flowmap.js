// SPDX-License-Identifier: BSD-3-Clause
// Loads the flow-map WebAssembly page. No inline script (the page's CSP
// forbids it); the credentials come from the URL fragment, which is never sent
// to a server: #class=<id>&ticket=<map ticket> (the teacher, from
// `wctr-relay flowmap`) or #class=<id>&session=<session token> (a student).
"use strict";
(function () {
  const params = new URLSearchParams(location.hash.slice(1));
  // Forget the credentials in the address bar once read.
  history.replaceState(null, "", location.pathname);
  globalThis.wctrFlowmapConfig = {
    classId: params.get("class") || "",
    ticket: params.get("ticket") || "",
    session: params.get("session") || "",
    base: location.origin,
  };
  const status = document.getElementById("status");
  const go = new Go();
  fetch("flowmap.wasm")
    .then((resp) => {
      if (!resp.ok) {
        return resp.text().then((t) => { throw new Error(t || resp.statusText); });
      }
      return WebAssembly.instantiateStreaming(resp, go.importObject);
    })
    .then((r) => go.run(r.instance))
    .catch((e) => { status.textContent = "the flow map cannot start: " + e.message; });
  const filter = document.getElementById("filter");
  filter.addEventListener("input", () => {
    if (typeof globalThis.wctrFlowmapFilter === "function") {
      globalThis.wctrFlowmapFilter(filter.value);
    }
  });
})();
