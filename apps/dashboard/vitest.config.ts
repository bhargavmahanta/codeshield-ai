import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    globals: true,
    include: ["**/*.test.ts", "**/*.test.tsx"],
    setupFiles: ["./vitest.setup.ts"]
  },
  resolve: {
    alias: {
      "@": new URL(".", import.meta.url).pathname
    }
  }
});
