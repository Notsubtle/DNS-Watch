import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Defaults to the local backend; the UAT stack sets VITE_PROXY_TARGET so
      // the dev server proxies to the `api` container instead of localhost.
      "/api": process.env.VITE_PROXY_TARGET || "http://localhost:8090",
    },
  },
});
