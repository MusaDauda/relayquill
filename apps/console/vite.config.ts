import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const STRICT_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'";

const DEV_CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws://localhost:5205 http://localhost:5205; base-uri 'self'; form-action 'self'; object-src 'none'";

function consoleSecurityHeadersPlugin(): Plugin {
  let isServeMode = false;
  return {
    name: "relayquill-console-csp",
    configResolved(resolved) {
      isServeMode = resolved.command === "serve";
    },
    transformIndexHtml: {
      order: "post",
      handler(html) {
        const targetCsp = isServeMode ? DEV_CSP : STRICT_CSP;
        return html.replace(
          /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*"\s*\/>/,
          `<meta http-equiv="Content-Security-Policy" content="${targetCsp}" />`
        );
      }
    }
  };
}

export default defineConfig({
  plugins: [react(), consoleSecurityHeadersPlugin()],
  server: {
    host: "localhost",
    port: 5205,
    strictPort: true,
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8005",
        changeOrigin: false
      }
    }
  },
  preview: {
    host: "localhost",
    port: 5205,
    strictPort: true,
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8005",
        changeOrigin: false
      }
    }
  }
});
