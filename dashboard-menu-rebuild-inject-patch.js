import fs from "fs";

const file = "server.js";
const menuScript = '<script src="/dashboard-menu-rebuild.js"></script>';
const colorScript = '<script src="/dashboard-color-theme.js"></script>';
const scripts = menuScript + colorScript;

if (!fs.existsSync(file)) {
  console.warn("[dashboard-menu-rebuild-inject-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const before = source;

if (!source.includes('/dashboard-menu-rebuild.js')) {
  source = source.replace(
    '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>',
    '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>' + scripts
  );

  source = source.replace(
    'const injection = \'<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>\';',
    'const injection = \'<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script><script src="/dashboard-menu-rebuild.js"></script><script src="/dashboard-color-theme.js"></script>\';'
  );
}

if (source.includes('/dashboard-menu-rebuild.js') && !source.includes('/dashboard-color-theme.js')) {
  source = source.replace('<script src="/dashboard-menu-rebuild.js"></script>', scripts);
}

if (source !== before) {
  fs.writeFileSync(file, source);
  console.log("Rebuilt dashboard menu and color theme scripts injected.");
} else {
  console.log("Rebuilt dashboard menu and color theme scripts already injected or no target found.");
}
