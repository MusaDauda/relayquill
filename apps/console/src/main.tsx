import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { CONSOLE_APP_VERSION } from "./index.js";

const rootElement = document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(
    <StrictMode>
      <main data-version={CONSOLE_APP_VERSION}>
        <h1>Relayquill Console</h1>
      </main>
    </StrictMode>
  );
}
