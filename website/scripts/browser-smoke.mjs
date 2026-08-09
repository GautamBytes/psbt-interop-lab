import { readFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const websiteDirectory = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repositoryDirectory = resolve(websiteDirectory, "..");
const distDirectory = join(websiteDirectory, "dist");
const vercel = JSON.parse(await readFile(join(repositoryDirectory, "vercel.json"), "utf8"));
const configuredHeaders = Object.fromEntries(
  vercel.headers.flatMap((rule) => rule.headers.map(({ key, value }) => [key, value])),
);

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
};

async function resolveAsset(pathname) {
  const requested = normalize(decodeURIComponent(pathname)).replace(/^(\.\.(\/|\\|$))+/, "");
  const candidate = join(distDirectory, requested);

  if (candidate.startsWith(distDirectory)) {
    try {
      if ((await stat(candidate)).isFile()) return candidate;
    } catch {
      // The production rewrite serves index.html for application routes.
    }
  }

  return join(distDirectory, "index.html");
}

const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url ?? "/", "http://localhost").pathname;
    const file = await resolveAsset(pathname);
    const body = await readFile(file);
    response.writeHead(200, {
      ...configuredHeaders,
      "Content-Type": contentTypes[extname(file)] ?? "application/octet-stream",
    });
    response.end(body);
  } catch (error) {
    response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    response.end(error instanceof Error ? error.message : String(error));
  }
});

await new Promise((resolveListen, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolveListen);
});

const address = server.address();
if (!address || typeof address === "string") throw new Error("Browser smoke server did not bind");

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const browserErrors = [];
page.on("console", (message) => {
  if (message.type() === "error") browserErrors.push(`console: ${message.text()}`);
});
page.on("pageerror", (error) => browserErrors.push(`page: ${error.message}`));
page.on("requestfailed", (request) =>
  browserErrors.push(`request: ${request.url()} (${request.failure()?.errorText ?? "failed"})`),
);

try {
  const origin = `http://127.0.0.1:${address.port}`;
  const architectureResponse = await page.goto(`${origin}/docs/architecture`, {
    waitUntil: "networkidle",
  });
  if (!architectureResponse?.ok()) throw new Error("Architecture route did not load successfully");
  if (!architectureResponse.headers()["content-security-policy"]?.includes("script-src 'self'")) {
    throw new Error("Production Content-Security-Policy header was not applied");
  }

  await page.locator(".mermaid-diagram__canvas > svg").waitFor({ state: "visible" });
  const theme = await page.locator("html").getAttribute("data-theme");
  if (theme !== "dark" && theme !== "light") {
    throw new Error("External theme bootstrap did not set a supported theme");
  }

  await page.goto(origin, { waitUntil: "networkidle" });
  const proofImages = page.locator(".proof-media img");
  if ((await proofImages.count()) !== 2) throw new Error("Expected two walkthrough proof images");
  for (let index = 0; index < 2; index += 1) {
    const loaded = await proofImages
      .nth(index)
      .evaluate((image) => image.complete && image.naturalWidth > 0);
    if (!loaded) throw new Error(`Walkthrough proof image ${index + 1} did not load`);
  }

  if (browserErrors.length > 0) throw new Error(browserErrors.join("\n"));
  console.log("Browser smoke passed: CSP, theme bootstrap, Mermaid, and proof images.");
} finally {
  await browser.close();
  await new Promise((resolveClose, reject) =>
    server.close((error) => (error ? reject(error) : resolveClose())),
  );
}
