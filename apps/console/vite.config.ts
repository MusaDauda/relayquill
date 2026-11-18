import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "localhost",
    port: 5205,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8005",
        changeOrigin: false
      }
    }
  }
});
