// Browser smoke test (run after smoke.sh, which creates the users): npm i playwright-core && node ui.mjs
// Uses /usr/bin/google-chrome; set the path in chromium.launch() for other systems.
import { chromium } from "playwright-core";
const B = "http://localhost:5173";
const browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox"] });
const out = [];
const check = (name, ok) => { out.push(`${ok ? "PASS" : "FAIL"} ${name}`); };
async function dismiss(page) {
  await page.waitForTimeout(2500);
  for (let i = 0; i < 3; i++) {
    if (await page.locator("[role=dialog]").count()) {
      out.push("info: dismissed dialog: " + (await page.locator("[role=dialog]").first().innerText()).slice(0, 80).replace(/\n/g, " "));
      await page.keyboard.press("Escape");
      await page.waitForTimeout(500);
    }
  }
}
async function login(page, u, p) {
  await page.goto(B + "/");
  await page.getByTestId("selfhosted-login-form").waitFor({ timeout: 30000 });
  await page.fill("#selfhosted-username", u);
  await page.fill("#selfhosted-password", p);
  await page.click("button[type=submit]");
}
// admin
let ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
let page = await ctx.newPage();
await login(page, "admin", "nope-nope-nope");
await page.getByRole("alert").waitFor({ timeout: 10000 });
check("wrong password shows error: " + (await page.getByRole("alert").innerText()), true);
await page.fill("#selfhosted-password", "Admin-Pass-E2E-2026");
await page.click("button[type=submit]");
await page.getByTestId("selfhosted-user-menu").waitFor({ timeout: 60000 });
check("admin lands in app, url=" + page.url(), page.url().includes("/default"));
await page.screenshot({ path: "ui-admin-home.png" });
await dismiss(page);
await page.getByTestId("selfhosted-user-menu").click();
const menu = await page.getByRole("menu").innerText();
check("admin menu has admin links", menu.includes("Users & roles") && menu.includes("Audit log"));
await page.keyboard.press("Escape");
await page.goto(B + "/default/admin/users");
await page.getByText("vi", { exact: true }).waitFor({ timeout: 30000 });
check("users page lists ed & vi", (await page.content()).includes(">ed<"));
await page.screenshot({ path: "ui-admin-users.png", fullPage: true });
await page.goto(B + "/default/admin/audit");
await page.getByText("auth.login.success").first().waitFor({ timeout: 30000 });
check("audit page shows events", true);
await page.screenshot({ path: "ui-admin-audit.png", fullPage: true });
await page.goto(B + "/default/account/api-keys");
await page.getByRole("button", { name: "Create API key" }).waitFor({ timeout: 30000 });
check("my api keys page", true);
await ctx.close();
// viewer
ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
page = await ctx.newPage();
await login(page, "vi", "Viewer-Final-Pass-2026");
await page.getByTestId("selfhosted-user-menu").waitFor({ timeout: 60000 });
await dismiss(page);
await page.getByTestId("selfhosted-user-menu").click();
const vmenu = await page.getByRole("menu").innerText();
check("viewer menu has no admin links", !vmenu.includes("Users & roles") && !vmenu.includes("Audit log"));
await page.keyboard.press("Escape");
await page.goto(B + "/default/admin/users");
await page.getByText("You don't have permission").waitFor({ timeout: 30000 });
check("viewer blocked from admin page", true);
await page.goto(B + "/default/projects");
await page.waitForTimeout(4000);
await page.screenshot({ path: "ui-viewer-projects.png" });
const createBtns = await page.getByRole("button", { name: /create project/i }).count();
check("viewer sees no create-project button (count=" + createBtns + ")", createBtns === 0);
await dismiss(page);
await page.getByTestId("selfhosted-user-menu").click();
await page.getByTestId("selfhosted-logout").click();
await page.getByTestId("selfhosted-login-form").waitFor({ timeout: 30000 });
check("logout returns to login", true);
await ctx.close();
// editor
ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
page = await ctx.newPage();
await login(page, "ed", "Editor-Final-Pass-2026");
await page.getByTestId("selfhosted-user-menu").waitFor({ timeout: 60000 });
await page.goto(B + "/default/projects");
await page.waitForTimeout(4000);
await page.screenshot({ path: "ui-editor-projects.png" });
const ecreate = await page.getByRole("button", { name: /create project/i }).count();
check("editor sees create-project button (count=" + ecreate + ")", ecreate > 0);
await browser.close();
console.log(out.join("\n"));
