const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");

const envPath = path.join(__dirname, ".env");
const defaults = {
  HOST: "127.0.0.1",
  PORT: "3000",
  ADMIN_PASSWORD: crypto.randomBytes(24).toString("base64url"),
  DATA_ENCRYPTION_KEY: crypto.randomBytes(32).toString("base64"),
  SESSION_SECRET: crypto.randomBytes(32).toString("base64"),
  TWELVE_DATA_API_KEY: "",
  NODE_ENV: "development"
};

try {
  let addedKeys = Object.keys(defaults);
  try {
    const current = fs.readFileSync(envPath, "utf8");
    const presentKeys = new Set(current.split(/\r?\n/).map((line) => line.match(/^([A-Z_]+)=/)?.[1]).filter(Boolean));
    addedKeys = Object.keys(defaults).filter((key) => !presentKeys.has(key));
    if (addedKeys.length > 0) {
      const separator = current.length > 0 && !current.endsWith("\n") ? "\n" : "";
      fs.writeFileSync(envPath, separator + addedKeys.map((key) => `${key}=${defaults[key]}`).join("\n") + "\n", { flag: "a", mode: 0o600 });
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    fs.writeFileSync(envPath, Object.entries(defaults).map(([key, value]) => `${key}=${value}`).join("\n") + "\n", { flag: "wx", mode: 0o600 });
  }
  console.log(addedKeys.length === 0 ? ".env already has all required settings." : `Added missing settings to .env: ${addedKeys.join(", ")}`);
} catch (error) {
  console.error("Could not create or update .env.", error);
  process.exitCode = 1;
}
