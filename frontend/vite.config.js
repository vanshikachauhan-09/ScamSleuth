import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the React app calls /api/..., which Vite forwards to FastAPI.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
