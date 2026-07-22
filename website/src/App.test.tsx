import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { installCommand } from "./content";

describe("PSBT Interop Lab website", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  afterEach(cleanup);

  it("renders the approved hero and real compatibility finding", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: /catch psbt handoff failures before users do/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/run the same transaction through real bitcoin libraries/i),
    ).toBeInTheDocument();
    expect(screen.getByText("Dockerless parser checks")).toBeInTheDocument();
    expect(
      screen.getByText("Target one scenario or category for faster iteration"),
    ).toBeInTheDocument();
    expect(screen.getByText("Native parser duplicate-key probe")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Run quickstart" })).toHaveAttribute(
      "href",
      "/docs#quick-start",
    );
    expect(screen.getByText(/quickstart proves one real handoff/i)).toBeInTheDocument();
    expect(screen.getByText(/matrix runs all 31 bundled scenarios/i)).toBeInTheDocument();
    expect(screen.getByText("PSBT Interop Lab 0.6.0")).toBeInTheDocument();
    expect(screen.getByText(/available now as version 0\.6\.0/i)).toBeInTheDocument();
  });

  it("shows a real command-to-report proof walkthrough", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: /from one command to a policy-accepted transaction/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/evidence from a real v0\.5\.2 quickstart/i)).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /v0\.5\.2 quickstart terminal output/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /v0\.5\.2 generated quickstart report/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open the complete walkthrough/i })).toHaveAttribute(
      "href",
      "/docs#walkthrough-verify-your-first-real-handoff",
    );
  });

  it("copies the pinned install command", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Copy install command" }));

    expect(screen.getByText(installCommand)).toBeInTheDocument();
    expect(installCommand).toContain("psbt-interop-lab@0.6.0");
    expect(screen.getByText("Install command copied")).toBeInTheDocument();
  });

  it("switches report evidence when another scenario is selected", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: /four-library roundtrip/i }));

    expect(screen.getByText("Metadata-rich P2WSH roundtrip")).toBeInTheDocument();
    expect(
      screen.getByText(/transaction intent, known fields, unknown fields/i),
    ).toBeInTheDocument();
  });

  it("shows a catalog-backed preview of structured conformance diagnostics", () => {
    render(<App />);

    expect(screen.getByText("Conformance report fields")).toBeInTheDocument();
    expect(screen.queryByText("v0.5.4 report output")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Classification" })).toBeInTheDocument();
    expect(screen.getByText("Implementation divergence")).toBeInTheDocument();
    expect(screen.getByText("Unique PSBT map keys")).toBeInTheDocument();
    expect(screen.getByText("btcsuite-go")).toBeInTheDocument();
    expect(screen.getByText("Code or dependency change")).toBeInTheDocument();
    expect(
      screen.getByText("finding:btcsuite-go-duplicate-global-key-accepted"),
    ).toBeInTheDocument();
    expect(screen.getByText("bip174.map-keys.unique")).toBeInTheDocument();
    expect(screen.getByText("must")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /BIP174.*Specification/i })).toHaveAttribute(
      "href",
      "https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki",
    );
  });

  it("attributes the empty final scriptSig finding only to rust-psbt", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: /PSBTv2 finalization/i }));

    expect(screen.getByText("bip174.final-scriptsig.empty-omitted")).toBeInTheDocument();
    const classification = screen
      .getByRole("heading", { name: "Classification" })
      .closest("section");
    if (!classification) throw new Error("Missing classification section");
    expect(within(classification).getByText("rust-psbt-v2")).toBeInTheDocument();
    expect(
      screen.getAllByText(/empty final scriptSig is represented by omitting/i).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText(
        /libwally strictly reject(?:ed|s) the explicit empty field as noncanonical/i,
      ),
    ).toBeInTheDocument();
    expect(within(classification).queryByText("rust-psbt-v2 / libwally")).not.toBeInTheDocument();
  });

  it("opens and filters project search", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Search documentation" }));
    const search = screen.getByRole("searchbox", { name: "Search documentation" });
    await user.type(search, "security");

    expect(screen.getByRole("dialog", { name: "Find documentation" })).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /security.*read the safety model/i }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /quick start/i })).not.toBeInTheDocument();
  });

  it("toggles theme and mobile navigation state", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Switch to light theme" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");

    const menuButton = screen.getByRole("button", { name: "Open navigation" });
    await user.click(menuButton);
    expect(menuButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("navigation", { name: "Mobile navigation" })).toBeInTheDocument();
  });
});
