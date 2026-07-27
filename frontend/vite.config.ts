import path from "node:path";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vite";

// Vite 8 may rewrite optional peer imports of @shadcn/react to a stub module that
// does not re-export jsx/jsxs. Force those stubs back to real React runtimes.
function resolveOptionalReactPeers(): Plugin {
  const reactRoot = path.resolve(__dirname, "node_modules/react");
  return {
    name: "resolve-optional-react-peers",
    enforce: "pre",
    resolveId(id) {
      if (id.startsWith("__vite-optional-peer-dep:react/jsx-runtime:")) {
        return path.join(reactRoot, "jsx-runtime.js");
      }
      if (id.startsWith("__vite-optional-peer-dep:react/jsx-dev-runtime:")) {
        return path.join(reactRoot, "jsx-dev-runtime.js");
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [resolveOptionalReactPeers(), react(), tailwindcss()],
  define: {
    __GROK2API_DEV_API_TARGET__: JSON.stringify(process.env.VITE_DEV_API_TARGET ?? ""),
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      react: path.resolve(__dirname, "node_modules/react"),
      "react-dom": path.resolve(__dirname, "node_modules/react-dom"),
      "react/jsx-runtime": path.resolve(__dirname, "node_modules/react/jsx-runtime.js"),
      "react/jsx-dev-runtime": path.resolve(__dirname, "node_modules/react/jsx-dev-runtime.js"),
    },
    dedupe: ["react", "react-dom"],
  },
  server: {
    port: 5173,
    proxy: {
      "/api": process.env.VITE_DEV_API_TARGET ?? "http://127.0.0.1:8000",
      "/v1": process.env.VITE_DEV_API_TARGET ?? "http://127.0.0.1:8000",
      "/healthz": process.env.VITE_DEV_API_TARGET ?? "http://127.0.0.1:8000",
      "/readyz": process.env.VITE_DEV_API_TARGET ?? "http://127.0.0.1:8000",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
