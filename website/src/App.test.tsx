import { cleanup, render, screen } from "@testing-library/react";
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
    expect(screen.getByText("Native parser duplicate-key probe")).toBeInTheDocument();
  });

  it("copies the pinned install command", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Copy install command" }));

    expect(screen.getByText(installCommand)).toBeInTheDocument();
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
