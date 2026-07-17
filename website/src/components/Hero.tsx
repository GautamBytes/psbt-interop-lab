import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import { FileCode } from "@phosphor-icons/react/FileCode";
import { Flask } from "@phosphor-icons/react/Flask";
import { FlowArrow } from "@phosphor-icons/react/FlowArrow";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { TerminalWindow } from "@phosphor-icons/react/TerminalWindow";
import { repositoryUrl } from "../content";
import { InstallCommand } from "./InstallCommand";

const metrics = [
  { icon: Flask, label: "24 scenarios" },
  { icon: FlowArrow, label: "6 implementations" },
  { icon: ShieldCheck, label: "regtest only" },
  { icon: FileCode, label: "replayable artifacts" },
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
          <a className="button button--primary" href="#matrix">
            <TerminalWindow aria-hidden="true" />
            Run the matrix
          </a>
          <a className="button button--text" href={repositoryUrl}>
            View on GitHub
            <ArrowSquareOut aria-hidden="true" />
          </a>
        </div>
        <InstallCommand />
        <div className="hero__metrics" aria-label="Project coverage">
          {metrics.map(({ icon: Icon, label }) => (
            <span key={label}>
              <Icon aria-hidden="true" />
              {label}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
