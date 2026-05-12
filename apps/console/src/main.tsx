import React from "react";
import { createRoot } from "react-dom/client";
import "@mindburn/ui-core/styles.css";
import "@copilotkit/react-core/v2/styles.css";
import "./styles.css";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) {
  throw new Error("HELM Console root element was not found.");
}

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
