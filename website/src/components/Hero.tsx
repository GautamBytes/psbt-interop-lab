import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import { Flask } from "@phosphor-icons/react/Flask";
import { FlowArrow } from "@phosphor-icons/react/FlowArrow";
import { HardDrives } from "@phosphor-icons/react/HardDrives";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { TerminalWindow } from "@phosphor-icons/react/TerminalWindow";
import { repositoryUrl } from "../content";
import { InstallCommand } from "./InstallCommand";
import { SiteLink } from "./SiteLink";

const metrics = [
  { icon: Flask, label: "31 scenarios" },
  { icon: FlowArrow, label: "7 implementations" },
  { icon: ShieldCheck, label: "regtest only" },
  { icon: HardDrives, label: "Dockerless parser checks" },
] as const;

export function Hero() {
  return (
    <section className="hero" id="top" aria-labelledby="hero-title">
      <div className="hero__asset" aria-hidden="true" />
      <div className="hero__content page-shell">
        <div className="hero__eyebrow">
          <Flask aria-hidden="true" weight="duotone" />
          <span>PSBT Interop Lab</span>
        </div>
        <h1 id="hero-title">
          Catch PSBT handoff failures <span>before</span> users do.
        </h1>
        <p>
          Run the same transaction through real Bitcoin libraries.
          <br />
          Preserve intent, signatures, and metadata. Replay every failure.
        </p>
        <div className="hero__actions">
          <SiteLink className="button button--primary" href="/docs#quick-start">
            <TerminalWindow aria-hidden="true" />
            Run quickstart
          </SiteLink>
          <a className="button button--text" href={repositoryUrl}>
            View on GitHub
            <ArrowSquareOut aria-hidden="true" />
          </a>
        </div>
        <InstallCommand />
        <p className="hero__mode-note">
          <span>Quickstart proves one real handoff.</span>
          <span>Matrix runs all 31 bundled scenarios.</span>
        </p>
        <ul className="hero__metrics" aria-label="Project coverage">
          {metrics.map(({ icon: Icon, label }) => (
            <li key={label}>
              <Icon aria-hidden="true" />
              {label}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
