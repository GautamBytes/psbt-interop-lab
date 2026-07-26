import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import cliProof from "../../../docs/assets/walkthrough/cli-finding-and-replay.png";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import { SiteLink } from "./SiteLink";

const facts = [
  {
    label: "P2 frontier",
    value: "2 / 2 protocol scenarios passed",
  },
  {
    label: "Coverage",
    value: "BIP373 MuSig2 and HWI-compatible simulator",
  },
  {
    label: "Replay",
    value: "6 checkpoints verified from the same artifact",
  },
] as const;

export function ProofWalkthrough() {
  return (
    <section className="proof-section" id="proof" aria-labelledby="proof-title">
      <div className="page-shell">
        <header className="proof-heading">
          <div>
            <span className="eyebrow">Evidence from the real v0.7.0 P2 proof</span>
            <h2 id="proof-title">Two protocol frontiers, one replayable artifact.</h2>
          </div>
          <div>
            <p>
              This filtered branch run preserves BIP373 fields through independent PSBT parsers,
              completes a two-process MuSig2 signing session, and exercises an HWI-compatible
              confirmation and key-origin policy. The generated report records every adapter cell,
              Core-backed outcome, and six replay-verified checkpoints from the same run.
            </p>
            <SiteLink
              className="inline-link"
              href="/docs#walkthrough-verify-the-p2-protocol-frontier"
            >
              Open the complete walkthrough <ArrowSquareOut aria-hidden="true" />
            </SiteLink>
          </div>
        </header>

        <div className="proof-media">
          <figure>
            <a href={cliProof} aria-label="Open full-size CLI proof">
              <img
                src={cliProof}
                alt="v0.7.0 P2 protocol proof terminal output"
                loading="lazy"
                decoding="async"
              />
            </a>
            <figcaption>
              <span>01</span>
              <strong>Run the P2 proof</strong>
              <small>Two focused scenarios covering MuSig2 and simulated hardware signing.</small>
            </figcaption>
          </figure>

          <figure>
            <a href={reportProof} aria-label="Open full-size generated report">
              <img
                src={reportProof}
                alt="v0.7.0 generated P2 protocol report"
                loading="lazy"
                decoding="async"
              />
            </a>
            <figcaption>
              <span>02</span>
              <strong>Inspect the report</strong>
              <small>Direct capture of the two-scenario, self-contained HTML artifact.</small>
            </figcaption>
          </figure>
        </div>

        <dl className="proof-facts">
          {facts.map((fact) => (
            <div key={fact.label}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
