import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    allowedHosts: ["terminal.local"],
    fs: {
      allow: [".."],
    },
  },
  test: {
    environment: "happy-dom",
    setupFiles: "./src/test/setup.ts",
    css: true,
  },
});
