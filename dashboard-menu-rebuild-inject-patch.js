import fs from "fs";

const file = "server.js";
const script = '<script src="/dashboard-menu-rebuild.js"></script>';

if (!fs.existsSync(file)) {
  console.warn("[dashboard-menu-rebuild-inject-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const before = source;

if (!source.includes('/dashboard-menu-rebuild.js')) {
  source = source.replace(
    '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>',
    '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>' + script
  );

  source = source.replace(
    'const injection = \'<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>\';',
    'const injection = \'<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script><script src="/dashboard-menu-rebuild.js"></script>\';'
  );
}

if (source !== before) {
  fs.writeFileSync(file, source);
  console.log("Rebuilt dashboard menu script injected.");
} else {
  console.log("Rebuilt dashboard menu script already injected or no target found.");
}
