import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { resolveDocumentHref } from "./components/MarkdownPage";
import { documents } from "./pages/documents";

describe("website documentation routes", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    window.localStorage.clear();
  });

  afterEach(cleanup);

  it.each([
    ["/docs", "PSBT Interop Lab", /local developer tool for finding interoperability failures/i],
    ["/adapter-kit", "External Adapter Guide", /enroll conforming adapters in the full matrix/i],
    ["/security", "Security Model", /boundary is kept intentionally smaller/i],
    ["/docs/architecture", "Architecture", /proof suite answers one concrete question/i],
    ["/docs/future-work", "Future Work", /driven by real wallet and library maintainers/i],
    ["/docs/sources", "Official Source Ledger", /primary sources used to choose protocol behavior/i],
    ["/security/threat-model", "PSBT Interop Lab Threat Model", /local generated-regtest workflow/i],
  ])("renders %s from repository Markdown", (pathname, heading, text) => {
    window.history.replaceState({}, "", pathname);
    render(<App />);

    expect(screen.getByRole("heading", { level: 1, name: heading })).toBeInTheDocument();
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it("uses internal primary navigation and changes pages without reloading", async () => {
    const user = userEvent.setup();
    render(<App />);

    const primaryNavigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    const docs = primaryNavigation.getByRole("link", { name: "Docs" });
    expect(docs).toHaveAttribute("href", "/docs");
    expect(primaryNavigation.getByRole("link", { name: "Adapter kit" })).toHaveAttribute("href", "/adapter-kit");
    expect(primaryNavigation.getByRole("link", { name: "Security" })).toHaveAttribute("href", "/security");

    await user.click(docs);

    expect(window.location.pathname).toBe("/docs");
    expect(screen.getByRole("heading", { level: 1, name: "PSBT Interop Lab" })).toBeInTheDocument();
  });

  it("responds to browser history navigation", () => {
    window.history.replaceState({}, "", "/docs");
    render(<App />);

    act(() => {
      window.history.pushState({}, "", "/security");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });

    expect(screen.getByRole("heading", { level: 1, name: "Security Model" })).toBeInTheDocument();
  });

  it("does not leak Markdown parser metadata into the DOM", () => {
    window.history.replaceState({}, "", "/docs");
    render(<App />);

    expect(screen.getByRole("link", { name: "the adapter guide" })).not.toHaveAttribute("node");
  });

  it("keeps linked repository Markdown inside the website", () => {
    window.history.replaceState({}, "", "/docs");
    render(<App />);

    expect(screen.getByRole("link", { name: "the architecture" })).toHaveAttribute("href", "/docs/architecture");
    expect(screen.getByRole("link", { name: "future work" })).toHaveAttribute("href", "/docs/future-work");
    expect(screen.getByRole("link", { name: "official source ledger" })).toHaveAttribute("href", "/docs/sources");
    expect(screen.getByRole("link", { name: "threat model" })).toHaveAttribute("href", "/security/threat-model");
  });

  it("keeps every local repository link in mirrored Markdown inside the website", () => {
    const markdownLink = /\[[^\]]+\]\(([^)]+)\)/g;

    for (const document of documents) {
      for (const match of document.markdown.matchAll(markdownLink)) {
        const href = match[1];
        if (/^(?:https?:|mailto:|#)/.test(href)) continue;

        expect(
          resolveDocumentHref(href, document.baseDir),
          `${document.sourcePath} should keep ${href} inside the website`,
        ).toMatch(/^\//);
        expect(resolveDocumentHref(href, document.baseDir)).not.toContain("github.com");
      }
    }
  });

  it.each([
    ["manifest schema", "/files/src/conformance/adapter-manifest.schema.json"],
    ["example", "/files/examples/custom-suite.json"],
    ["schema", "/files/src/custom/suite-manifest.schema.json"],
    ["website/", "/files/website"],
  ])("routes the README %s reference to its internal file page", (name, href) => {
    window.history.replaceState({}, "", "/docs");
    render(<App />);

    expect(screen.getByRole("link", { name })).toHaveAttribute("href", href);
  });

  it.each([
    ["/files/src/conformance/adapter-manifest.schema.json", "Adapter manifest schema", /psbt-lab\.adapters/],
    ["/files/src/custom/suite-manifest.schema.json", "Custom suite schema", /p2tr-scriptpath/],
    ["/files/examples/custom-suite.json", "Custom suite example", /nested-to-taproot/],
    ["/files/website", "Website source", /Vite application/],
  ])("renders the internal repository resource at %s", (pathname, heading, content) => {
    window.history.replaceState({}, "", pathname);
    render(<App />);

    expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    expect(screen.getByText(content)).toBeInTheDocument();
  });

  it("uses internal links for homepage documentation references", () => {
    render(<App />);

    expect(screen.getByRole("link", { name: /Read the full scenario list/i })).toHaveAttribute(
      "href",
      "/docs#current-coverage",
    );
    expect(screen.getByRole("link", { name: /View the schema/i })).toHaveAttribute(
      "href",
      "/files/src/conformance/adapter-manifest.schema.json",
    );
  });

  it("copies fenced documentation commands", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    window.history.replaceState({}, "", "/docs");
    render(<App />);

    const copyButtons = screen.getAllByRole("button", { name: "Copy code block" });
    expect(copyButtons.length).toBeGreaterThan(0);

    await user.click(copyButtons[0]);

    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("npm install --global"));
    expect(screen.getByText("Code block copied")).toBeInTheDocument();
  });

  it("renders a useful page for an unknown path", () => {
    window.history.replaceState({}, "", "/not-a-real-page");
    render(<App />);

    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Return home" })).toHaveAttribute("href", "/");
  });
});
