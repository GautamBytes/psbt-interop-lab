import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { installCommand } from "./content";

describe("PSBT Interop Lab website", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

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
      screen.getByText("Cryptographically measured ECDSA and Taproot sighash mutations"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Promote exact parser classifications and structural facts"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Target one scenario or category for faster iteration"),
    ).toBeInTheDocument();
    expect(screen.getByText("Native parser duplicate-key probe")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Run quickstart" })).toHaveAttribute(
      "href",
      "/docs#quick-start",
    );
    expect(screen.getByText(/quickstart proves one real handoff/i)).toBeInTheDocument();
    expect(screen.getByText(/matrix runs all 52 bundled scenarios/i)).toBeInTheDocument();
    expect(
      screen.getByText(/BIP373 MuSig2 nonce exchange, partial verification, and aggregation/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/HWI-compatible simulator confirmation and key-origin policy/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/BIP375 sender workflows and BIP376 receiver-spend workflow/i),
    ).toBeInTheDocument();
    expect(screen.getByText("PSBT Interop Lab 0.10.1")).toBeInTheDocument();
    expect(screen.getByText(/available now as version 0\.10\.1/i)).toBeInTheDocument();
    expect(screen.getByText(/v0\.10\.0 capture/i)).toBeInTheDocument();
  });

  it("replaces footer resources with the maintainer reach-out links", () => {
    render(<App />);

    const footer = screen.getByText("PSBT Interop Lab 0.10.1").closest("footer");
    if (!footer) throw new Error("Expected the site footer");
    const profiles = within(footer).getByRole("navigation", {
      name: "Gautam Manchandani profiles",
    });
    expect(within(footer).queryByRole("link", { name: "Security" })).not.toBeInTheDocument();
    expect(within(profiles).getByText("Reach out")).toBeInTheDocument();

    const links = [
      ["X", "https://x.com/GautamM96"],
      ["LinkedIn", "https://www.linkedin.com/in/gautam-manchandani/"],
      ["GitHub", "https://github.com/GautamBytes"],
    ] as const;

    for (const [name, href] of links) {
      expect(within(profiles).getByRole("link", { name })).toHaveAttribute("href", href);
      expect(within(profiles).getByRole("link", { name })).toHaveAttribute("target", "_blank");
      expect(within(profiles).getByRole("link", { name })).toHaveAttribute(
        "rel",
        "noreferrer noopener",
      );
    }
  });

  it("groups the complete coverage surface into four scannable areas", () => {
    render(<App />);

    const groups = [
      ["Transaction coverage", "Legacy P2PKH, nested SegWit, P2WSH, and Taproot fixtures"],
      ["Adversarial safety", "Cryptographically measured ECDSA and Taproot sighash mutations"],
      ["Protocol frontiers", "BIP373 MuSig2 nonce exchange, partial verification, and aggregation"],
      ["Developer workflow", "Wallet CI Action with external-only, JUnit, and SARIF output"],
    ] as const;

    for (const [heading, representativeClaim] of groups) {
      const group = screen.getByRole("heading", { level: 3, name: heading }).closest("section");
      expect(group).not.toBeNull();
      expect(within(group as HTMLElement).getAllByRole("listitem")).toHaveLength(4);
      expect(within(group as HTMLElement).getByText(representativeClaim)).toBeInTheDocument();
    }
  });

  it("routes each primary audience to a focused starting point", () => {
    render(<App />);

    const paths = screen.getByRole("region", {
      name: "Start with the job you need to finish.",
    });
    expect(within(paths).getByRole("link", { name: /i maintain a wallet/i })).toHaveAttribute(
      "href",
      "/adapter-kit",
    );
    expect(within(paths).getByRole("link", { name: /i maintain a library/i })).toHaveAttribute(
      "href",
      "/docs#differential-fuzzing",
    );
    expect(
      within(paths).getByRole("link", { name: /i review protocol behavior/i }),
    ).toHaveAttribute("href", "/docs#walkthrough-verify-the-complete-matrix");
  });

  it("shows a real command-to-report proof walkthrough", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: /the complete matrix, one replayable artifact/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/evidence from the complete 52-scenario matrix/i)).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /complete matrix generated report/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /silent payment conformance report evidence/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/52 bundled scenarios across 9 integration stacks/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/3 compatibility findings remained visible/i)).toBeInTheDocument();
    expect(
      screen.getByText(/101 checkpoints verified from the same artifact/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/2 \/ 2 protocol scenarios passed/i)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open the complete walkthrough/i })).toHaveAttribute(
      "href",
      "/docs#walkthrough-verify-the-complete-matrix",
    );
  });

  it("opens proof screenshots in a dismissible image viewer", async () => {
    const user = userEvent.setup();
    render(<App />);

    const trigger = screen.getByRole("button", {
      name: /open full-size complete matrix generated report/i,
    });
    await user.click(trigger);

    const dialog = screen.getByRole("dialog", {
      name: /complete matrix generated report full-size preview/i,
    });
    expect(dialog).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Close image preview" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("keeps keyboard focus inside the image viewer", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(
      screen.getByRole("button", {
        name: /open full-size complete matrix generated report/i,
      }),
    );

    const close = screen.getByRole("button", { name: "Close image preview" });
    expect(close).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    expect(close).toHaveFocus();
  });

  it("closes an enlarged screenshot from the backdrop or Escape, but not the image", async () => {
    const user = userEvent.setup();
    render(<App />);

    const trigger = screen.getByRole("button", {
      name: /open full-size complete matrix generated report/i,
    });
    await user.click(trigger);

    const openDialog = screen.getByRole("dialog");
    const previewImage = within(openDialog).getByRole("img", {
      name: /complete matrix generated report/i,
    });
    await user.click(previewImage);
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await user.click(trigger);
    const dialog = screen.getByRole("dialog");
    const backdrop = dialog.parentElement;
    if (!backdrop) throw new Error("Missing image preview backdrop");
    await user.click(backdrop);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("copies the pinned install command", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Copy install command" }));

    expect(screen.getByText(installCommand)).toBeInTheDocument();
    expect(installCommand).toContain("psbt-interop-lab@0.10.1");
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

  it("labels the report rail as samples and surfaces v0.10 Silent Payment evidence", async () => {
    const user = userEvent.setup();
    render(<App />);

    expect(screen.getByText("Sample scenarios")).toBeInTheDocument();
    expect(screen.getByText(/browse sample scenarios/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /BIP375 conformance/i }));
    expect(
      screen.getByRole("heading", { name: "Silent Payment field conformance" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/all 41 official BIP375 vectors/i)).toBeInTheDocument();
    expect(screen.getByText(/this sample highlights one of two/i)).toBeInTheDocument();
    expect(screen.getByText("bip375.invalid-vectors.rejected")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /BIP376 receiver spend/i }));
    expect(
      screen.getByRole("heading", { name: "Silent Payment receiver-spend handoff" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Core policy acceptance on regtest/i)).toBeInTheDocument();
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

  it("searches repository documentation content, traps focus, and restores the trigger", async () => {
    const user = userEvent.setup();
    render(<App />);

    const trigger = screen.getByRole("button", { name: "Search documentation" });
    await user.click(trigger);
    const search = screen.getByRole("searchbox", { name: "Search documentation" });
    await user.type(search, "nonce exchange");

    expect(screen.getByRole("link", { name: /architecture/i })).toBeInTheDocument();

    const close = screen.getByRole("button", { name: "Close search" });
    close.focus();
    await user.tab({ shift: true });
    expect(document.activeElement).toHaveAttribute("href");

    close.focus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Find documentation" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("toggles theme and mobile navigation state", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Switch to light theme" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(window.localStorage.getItem("psbt-lab-theme")).toBe("light");

    const menuButton = screen.getByRole("button", { name: "Open navigation" });
    await user.click(menuButton);
    expect(menuButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("navigation", { name: "Mobile navigation" })).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("navigation", { name: "Mobile navigation" })).not.toBeInTheDocument();
    expect(menuButton).toHaveFocus();
  });

  it("follows operating-system theme changes until the visitor chooses one", async () => {
    const user = userEvent.setup();
    let handleChange: ((event: { matches: boolean }) => void) | undefined;
    vi.stubGlobal(
      "matchMedia",
      vi.fn().mockReturnValue({
        matches: true,
        addEventListener: (_event: string, handler: (event: { matches: boolean }) => void) => {
          handleChange = handler;
        },
        removeEventListener: vi.fn(),
      }),
    );

    render(<App />);

    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(window.localStorage.getItem("psbt-lab-theme")).toBeNull();

    act(() => handleChange?.({ matches: false }));

    expect(document.documentElement).toHaveAttribute("data-theme", "dark");

    await user.click(screen.getByRole("button", { name: "Switch to light theme" }));
    act(() => handleChange?.({ matches: false }));

    expect(document.documentElement).toHaveAttribute("data-theme", "light");
  });
});
