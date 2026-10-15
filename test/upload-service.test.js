const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { WebSocket } = require("ws");
const { after, before, test } = require("node:test");

const root = path.resolve(__dirname, "..");
const adminPassword = "test-only-admin-password-123456";
let baseUrl;
let storageDir;
let service;
let serviceOutput = "";
let encryptionKey;

function encryptForTest(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value))), cipher.final()]);
  return Buffer.concat([Buffer.from([1]), iv, cipher.getAuthTag(), encrypted]);
}

function decryptForTest(cipherText) {
  const iv = cipherText.subarray(1, 13);
  const authTag = cipherText.subarray(13, 29);
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(cipherText.subarray(29)), decipher.final()]);
}

async function unusedPort() {
  const probe = net.createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForService() {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (service.exitCode !== null) throw new Error(`Upload service exited early: ${serviceOutput}`);
    try {
      const response = await fetch(`${baseUrl}/register.html`);
      if (response.ok) return;
    } catch (error) {
      if (error.cause?.code !== "ECONNREFUSED") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Upload service did not start: ${serviceOutput}`);
}

function makeForm(front, back) {
  const form = new FormData();
  form.set("fullName", "Test Demo User");
  form.set("email", "demo@example.test");
  form.set("accountPassword", "test-user-password-123");
  form.set("confirmPassword", "test-user-password-123");
  form.set("phone", "+1 555 010 0200");
  form.set("country", "United States");
  form.set("ssn", "123-45-6789");
  form.set("contactConsent", "on");
  form.append("driversLicenseFront", new Blob([front], { type: "image/png" }), "front.png");
  form.append("driversLicenseBack", new Blob([back], { type: "application/pdf" }), "back.pdf");
  return form;
}

before(async () => {
  const port = await unusedPort();
  storageDir = await fs.mkdtemp(path.join(os.tmpdir(), "aivestora-private-test-"));
  encryptionKey = crypto.randomBytes(32);
  baseUrl = `http://127.0.0.1:${port}`;
  service = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      NODE_ENV: "test",
      ADMIN_PASSWORD: adminPassword,
      DATA_ENCRYPTION_KEY: encryptionKey.toString("base64"),
      SESSION_SECRET: crypto.randomBytes(32).toString("base64"),
      TWELVE_DATA_API_KEY: "",
      PRIVATE_UPLOAD_DIR: storageDir
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  service.stdout.on("data", (chunk) => { serviceOutput += chunk; });
  service.stderr.on("data", (chunk) => { serviceOutput += chunk; });
  await waitForService();
});

after(async () => {
  if (service && service.exitCode === null) {
    service.kill();
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 3000);
      once(service, "exit").then(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  if (storageDir) await fs.rm(storageDir, { recursive: true, force: true });
});

test("accepts uploads, encrypts records, authorizes review, downloads files, and deletes submissions", async () => {
  const unauthorized = await fetch(`${baseUrl}/api/admin/submissions`);
  assert.equal(unauthorized.status, 401);
  const unauthorizedMarket = await fetch(`${baseUrl}/api/market/SPX`);
  assert.equal(unauthorizedMarket.status, 401);
  const protectedDashboard = await fetch(`${baseUrl}/dashboard.html`, { redirect: "manual" });
  assert.equal(protectedDashboard.status, 302);
  assert.equal(protectedDashboard.headers.get("location"), "/signin.html");

  const fakeForm = makeForm(Buffer.from("not actually a PNG"), Buffer.from("%PDF-1.7 test"));
  const rejectedUpload = await fetch(`${baseUrl}/api/submissions`, { method: "POST", body: fakeForm });
  assert.equal(rejectedUpload.status, 400);

  const front = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0]);
  const back = Buffer.from("%PDF-1.7\nfictional test document");
  const createdResponse = await fetch(`${baseUrl}/api/submissions`, {
    method: "POST",
    body: makeForm(front, back)
  });
  const created = await createdResponse.json();
  assert.equal(createdResponse.status, 201, JSON.stringify(created));
  const registrationCookieHeader = createdResponse.headers.get("set-cookie");
  assert.match(registrationCookieHeader, /HttpOnly/);
  assert.match(registrationCookieHeader, /SameSite=Strict/);
  const registrationCookie = registrationCookieHeader.split(";")[0];
  const registrationSession = await fetch(`${baseUrl}/api/auth/session`, {
    headers: { Cookie: registrationCookie }
  });
  assert.deepEqual(await registrationSession.json(), {
    email: "demo@example.test",
    name: "Test Demo User",
    balanceCents: 0
  });
  const marketWithoutKey = await fetch(`${baseUrl}/api/market/SPX`, {
    headers: { Cookie: registrationCookie }
  });
  assert.equal(marketWithoutKey.status, 503);
  assert.equal((await marketWithoutKey.json()).error, "Live market data is unavailable.");
  const marketStreamWithoutKey = await new Promise((resolve, reject) => {
    const socket = new WebSocket(`${baseUrl.replace(/^http/, "ws")}/api/market-stream?symbol=SPX`, {
      headers: { Cookie: registrationCookie }
    });
    const timeout = setTimeout(() => {
      socket.terminate();
      reject(new Error("Market stream handshake did not complete."));
    }, 3000);
    socket.on("unexpected-response", (request, response) => {
      clearTimeout(timeout);
      const status = response.statusCode;
      response.resume();
      socket.terminate();
      resolve(status);
    });
    socket.on("error", () => {});
  });
  assert.equal(marketStreamWithoutKey, 503);

  const authorization = `Basic ${Buffer.from(`admin:${adminPassword}`).toString("base64")}`;
  const listResponse = await fetch(`${baseUrl}/api/admin/submissions`, {
    headers: { Authorization: authorization }
  });
  assert.equal(listResponse.status, 200);
  const records = await listResponse.json();
  const record = records.find((item) => item.id === created.id);
  assert.ok(record);
  assert.equal(record.details.ssn, "123456789");
  assert.equal(Date.parse(record.expiresAt) - Date.parse(record.receivedAt), 30 * 24 * 60 * 60 * 1000);

  const encryptedRecord = await fs.readFile(path.join(storageDir, `${created.id}.record.enc`));
  const encryptedFront = await fs.readFile(path.join(storageDir, `${created.id}.front.enc`));
  const encryptedUsers = await fs.readFile(path.join(storageDir, "users.enc"));
  assert.equal(encryptedRecord.includes(Buffer.from("123456789")), false);
  assert.equal(encryptedFront.includes(front), false);
  assert.equal(encryptedUsers.includes(Buffer.from("test-user-password-123")), false);
  const accountAuthorization = `Basic ${Buffer.from(`admin:${adminPassword}`).toString("base64")}`;
  const accountListResponse = await fetch(`${baseUrl}/api/admin/accounts`, {
    headers: { Authorization: accountAuthorization }
  });
  assert.equal(accountListResponse.status, 200);
  const accounts = await accountListResponse.json();
  assert.equal(accounts.length, 1);
  assert.equal(accounts[0].email, "demo@example.test");
  assert.equal(accounts[0].fullName, "Test Demo User");
  assert.equal(accounts[0].balanceCents, 0);
  assert.equal(Object.hasOwn(accounts[0], "passwordHash"), false);

  const unauthorizedBalanceUpdate = await fetch(`${baseUrl}/api/admin/accounts/${accounts[0].id}/balance`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "add", amount: "20.00" })
  });
  assert.equal(unauthorizedBalanceUpdate.status, 401);

  const addBalanceResponse = await fetch(`${baseUrl}/api/admin/accounts/${accounts[0].id}/balance`, {
    method: "POST",
    headers: { Authorization: authorization, "Content-Type": "application/json" },
    body: JSON.stringify({ action: "add", amount: "125.75" })
  });
  assert.equal(addBalanceResponse.status, 200);
  assert.deepEqual(await addBalanceResponse.json(), { id: accounts[0].id, balanceCents: 12575 });

  const subtractBalanceResponse = await fetch(`${baseUrl}/api/admin/accounts/${accounts[0].id}/balance`, {
    method: "POST",
    headers: { Authorization: authorization, "Content-Type": "application/json" },
    body: JSON.stringify({ action: "subtract", amount: "25.50" })
  });
  assert.equal(subtractBalanceResponse.status, 200);
  assert.deepEqual(await subtractBalanceResponse.json(), { id: accounts[0].id, balanceCents: 10025 });

  const negativeBalanceResponse = await fetch(`${baseUrl}/api/admin/accounts/${accounts[0].id}/balance`, {
    method: "POST",
    headers: { Authorization: authorization, "Content-Type": "application/json" },
    body: JSON.stringify({ action: "subtract", amount: "100.26" })
  });
  assert.equal(negativeBalanceResponse.status, 400);
  assert.match((await negativeBalanceResponse.json()).error, /below \$0\.00/);
  const updatedAccountList = await fetch(`${baseUrl}/api/admin/accounts`, {
    headers: { Authorization: authorization }
  });
  assert.equal((await updatedAccountList.json())[0].balanceCents, 10025);
  const updatedRegistrationSession = await fetch(`${baseUrl}/api/auth/session`, {
    headers: { Cookie: registrationCookie }
  });
  assert.equal((await updatedRegistrationSession.json()).balanceCents, 10025);

  const wrongLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "demo@example.test", password: "incorrect-password-123" })
  });
  assert.equal(wrongLogin.status, 401);
  const usersPath = path.join(storageDir, "users.enc");
  const correctNameUsers = await fs.readFile(usersPath);
  const legacyUsers = JSON.parse(decryptForTest(correctNameUsers).toString("utf8")).map((user) => ({
    ...user,
    fullName: user.email
  }));
  await fs.writeFile(usersPath, encryptForTest(legacyUsers));
  const correctLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "DEMO@example.test", password: "test-user-password-123" })
  });
  assert.equal(correctLogin.status, 200);
  const repairedUsers = JSON.parse(decryptForTest(await fs.readFile(usersPath)).toString("utf8"));
  assert.equal(repairedUsers[0].fullName, "Test Demo User");
  const sessionCookie = correctLogin.headers.get("set-cookie").split(";")[0];
  assert.match(correctLogin.headers.get("set-cookie"), /HttpOnly/);
  assert.match(correctLogin.headers.get("set-cookie"), /SameSite=Strict/);
  const authorizedDashboard = await fetch(`${baseUrl}/dashboard.html`, {
    headers: { Cookie: sessionCookie },
    redirect: "manual"
  });
  assert.equal(authorizedDashboard.status, 200);
  const dashboardHtml = await authorizedDashboard.text();
  assert.match(dashboardHtml, /id="account-name"/);
  assert.doesNotMatch(dashboardHtml, /id="account-email"/);
  const session = await fetch(`${baseUrl}/api/auth/session`, { headers: { Cookie: sessionCookie } });
  assert.deepEqual(await session.json(), {
    email: "demo@example.test",
    name: "Test Demo User",
    balanceCents: 10025
  });
  const encryptedUsersBeforeLegacySession = await fs.readFile(usersPath);
  try {
    const usersWithoutName = JSON.parse(decryptForTest(encryptedUsersBeforeLegacySession).toString("utf8")).map((user) => ({
      ...user,
      fullName: "demo@example.test"
    }));
    await fs.writeFile(usersPath, encryptForTest(usersWithoutName));
    const legacySession = await fetch(`${baseUrl}/api/auth/session`, { headers: { Cookie: sessionCookie } });
    assert.equal((await legacySession.json()).name, "Test Demo User");
  } finally {
    await fs.writeFile(usersPath, encryptedUsersBeforeLegacySession);
  }

  for (const [side, expected] of [["front", front], ["back", back]]) {
    const download = await fetch(`${baseUrl}/api/admin/submissions/${created.id}/${side}`, {
      headers: { Authorization: authorization }
    });
    assert.equal(download.status, 200);
    assert.deepEqual(Buffer.from(await download.arrayBuffer()), expected);
  }

  const expiredRecord = {
    ...record,
    expiresAt: new Date(Date.now() - 1000).toISOString()
  };
  await fs.writeFile(
    path.join(storageDir, `${created.id}.record.enc`),
    encryptForTest(expiredRecord)
  );
  const expiredDownload = await fetch(`${baseUrl}/api/admin/submissions/${created.id}/front`, {
    headers: { Authorization: authorization }
  });
  assert.equal(expiredDownload.status, 404);
  assert.deepEqual(await fs.readdir(storageDir), ["users.enc"]);

  const accountAfterSubmissionExpiry = await fetch(`${baseUrl}/api/admin/accounts`, {
    headers: { Authorization: authorization }
  });
  assert.equal(accountAfterSubmissionExpiry.status, 200);
  assert.equal((await accountAfterSubmissionExpiry.json()).length, 1);
  const loginAfterSubmissionExpiry = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "demo@example.test", password: "test-user-password-123" })
  });
  assert.equal(loginAfterSubmissionExpiry.status, 200, "account remains usable after its identity submission expires");
  const retainedSession = loginAfterSubmissionExpiry.headers.get("set-cookie").split(";")[0];
  const retainedDashboard = await fetch(`${baseUrl}/dashboard.html`, {
    headers: { Cookie: retainedSession },
    redirect: "manual"
  });
  assert.equal(retainedDashboard.status, 200);

  const accountDeletion = await fetch(`${baseUrl}/api/admin/accounts/${accounts[0].id}`, {
    method: "DELETE",
    headers: { Authorization: authorization }
  });
  assert.equal(accountDeletion.status, 204);
  assert.deepEqual(await fs.readdir(storageDir), ["users.enc"]);
  const removedAccountLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "demo@example.test", password: "test-user-password-123" })
  });
  assert.equal(removedAccountLogin.status, 401);
  const removedAccountDashboard = await fetch(`${baseUrl}/dashboard.html`, {
    headers: { Cookie: retainedSession },
    redirect: "manual"
  });
  assert.equal(removedAccountDashboard.status, 302, "manually deleted accounts can no longer access the dashboard");

  const logout = await fetch(`${baseUrl}/api/auth/logout`, {
    method: "POST",
    headers: { Cookie: sessionCookie }
  });
  assert.equal(logout.status, 204);
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);
  const signedOutDashboard = await fetch(`${baseUrl}/dashboard.html`, {
    headers: { Cookie: logout.headers.get("set-cookie").split(";")[0] },
    redirect: "manual"
  });
  assert.equal(signedOutDashboard.status, 302);

  const nextAdminPassword = "test-only-new-admin-password-987654";
  const mismatchedAdminPassword = await fetch(`${baseUrl}/api/admin/password`, {
    method: "POST",
    headers: {
      Authorization: authorization,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      newPassword: nextAdminPassword,
      confirmPassword: "mismatched-password-123"
    })
  });
  assert.equal(mismatchedAdminPassword.status, 400);

  const adminPasswordChange = await fetch(`${baseUrl}/api/admin/password`, {
    method: "POST",
    headers: {
      Authorization: authorization,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      newPassword: nextAdminPassword,
      confirmPassword: nextAdminPassword
    })
  });
  assert.equal(adminPasswordChange.status, 200);
  assert.deepEqual(await adminPasswordChange.json(), { message: "Administrator password changed." });
  const encryptedAdminPassword = await fs.readFile(path.join(storageDir, "admin-password.enc"));
  assert.equal(encryptedAdminPassword.includes(Buffer.from(nextAdminPassword)), false);
  assert.equal(decryptForTest(encryptedAdminPassword).toString("utf8"), nextAdminPassword);

  const rejectedOldAdminPassword = await fetch(`${baseUrl}/api/admin/accounts`, {
    headers: { Authorization: authorization }
  });
  assert.equal(rejectedOldAdminPassword.status, 401);
  const acceptedNewAdminPassword = await fetch(`${baseUrl}/api/admin/accounts`, {
    headers: { Authorization: `Basic ${Buffer.from(`admin:${nextAdminPassword}`).toString("base64")}` }
  });
  assert.equal(acceptedNewAdminPassword.status, 200);

  const restartedPort = await unusedPort();
  const restartedBaseUrl = `http://127.0.0.1:${restartedPort}`;
  const restartedService = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(restartedPort),
      NODE_ENV: "test",
      ADMIN_PASSWORD: adminPassword,
      DATA_ENCRYPTION_KEY: encryptionKey.toString("base64"),
      SESSION_SECRET: crypto.randomBytes(32).toString("base64"),
      TWELVE_DATA_API_KEY: "",
      PRIVATE_UPLOAD_DIR: storageDir
    },
    stdio: ["ignore", "ignore", "ignore"]
  });
  try {
    const deadline = Date.now() + 8000;
    let ready = false;
    while (Date.now() < deadline) {
      if (restartedService.exitCode !== null) throw new Error("Restarted server exited before becoming available.");
      try {
        const response = await fetch(`${restartedBaseUrl}/register.html`);
        if (response.ok) {
          ready = true;
          break;
        }
      } catch (error) {
        if (error.cause?.code !== "ECONNREFUSED") throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(ready, true, "server restarts with the encrypted admin password");
    const persistedNewPassword = await fetch(`${restartedBaseUrl}/api/admin/accounts`, {
      headers: { Authorization: `Basic ${Buffer.from(`admin:${nextAdminPassword}`).toString("base64")}` }
    });
    assert.equal(persistedNewPassword.status, 200);
    const resetOldPassword = await fetch(`${restartedBaseUrl}/api/admin/accounts`, {
      headers: { Authorization: `Basic ${Buffer.from(`admin:${adminPassword}`).toString("base64")}` }
    });
    assert.equal(resetOldPassword.status, 401);
  } finally {
    if (restartedService.exitCode === null) {
      restartedService.kill();
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 3000);
        once(restartedService, "exit").then(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }
});

test("production identity submissions stay disabled until explicitly enabled", async () => {
  const port = await unusedPort();
  const productionStorage = await fs.mkdtemp(path.join(os.tmpdir(), "aivestora-production-test-"));
  const productionService = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: {
      ...process.env,
      HOST: "0.0.0.0",
      PORT: String(port),
      NODE_ENV: "production",
      ALLOW_PUBLIC_BIND: "true",
      TRUST_PROXY: "1",
      ENABLE_IDENTITY_SUBMISSIONS: "false",
      ADMIN_PASSWORD: adminPassword,
      DATA_ENCRYPTION_KEY: crypto.randomBytes(32).toString("base64"),
      SESSION_SECRET: crypto.randomBytes(32).toString("base64"),
      PRIVATE_UPLOAD_DIR: productionStorage
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let output = "";
  productionService.stderr.on("data", (chunk) => { output += chunk; });
  const productionUrl = `http://127.0.0.1:${port}`;
  try {
    const deadline = Date.now() + 8000;
    let ready = false;
    while (Date.now() < deadline) {
      if (productionService.exitCode !== null) {
        throw new Error(`Production service exited early: ${output}`);
      }
      try {
        const response = await fetch(`${productionUrl}/register.html`);
        if (response.ok) {
          ready = true;
          break;
        }
      } catch (error) {
        if (error.cause?.code !== "ECONNREFUSED") throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(ready, true, `Production service did not start: ${output}`);

    const response = await fetch(`${productionUrl}/api/submissions`, {
      method: "POST",
      headers: { "x-forwarded-proto": "https" }
    });
    assert.equal(response.status, 503);
    assert.match((await response.json()).error, /disabled pending production security review/);
  } finally {
    if (productionService.exitCode === null) {
      productionService.kill();
      await Promise.race([
        once(productionService, "exit"),
        new Promise((resolve) => setTimeout(resolve, 3000))
      ]);
    }
    await fs.rm(productionStorage, { recursive: true, force: true });
  }
});
