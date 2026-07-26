import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import cliProof from "../../../docs/assets/walkthrough/cli-finding-and-replay.png";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import { SiteLink } from "./SiteLink";

const facts = [
  {
    label: "P1 gate",
    value: "6 / 6 safety scenarios passed",
  },
  {
    label: "Coverage",
    value: "Legacy, nested multisig, sighash, signer, and combiner",
  },
  {
    label: "Replay",
    value: "17 checkpoints verified from the same artifact",
  },
] as const;

export function ProofWalkthrough() {
  return (
    <section className="proof-section" id="proof" aria-labelledby="proof-title">
      <div className="page-shell">
        <header className="proof-heading">
          <div>
            <span className="eyebrow">Evidence from the real v0.7.0 P1 gate</span>
            <h2 id="proof-title">Six safety proofs, one replayable artifact.</h2>
          </div>
          <div>
            <p>
              This filtered branch run covers legacy and nested signing, cryptographically measured
              sighash mutations, signer refusals, and deterministic combiner conflicts. The
              generated report records per-request adapter cells, Core-backed outcomes, and 17
              replay-verified checkpoints from the same run.
            </p>
            <SiteLink className="inline-link" href="/docs#walkthrough-verify-the-p1-safety-gate">
              Open the complete walkthrough <ArrowSquareOut aria-hidden="true" />
            </SiteLink>
          </div>
        </header>

        <div className="proof-media">
          <figure>
            <a href={cliProof} aria-label="Open full-size CLI proof">
              <img
                src={cliProof}
                alt="v0.7.0 P1 safety proof terminal output"
                loading="lazy"
                decoding="async"
              />
            </a>
            <figcaption>
              <span>01</span>
              <strong>Run the P1 gate</strong>
              <small>
                Six focused scenarios covering signing, sighashes, refusals, and conflicts.
              </small>
            </figcaption>
          </figure>

          <figure>
            <a href={reportProof} aria-label="Open full-size generated report">
              <img
                src={reportProof}
                alt="v0.7.0 generated P1 safety report"
                loading="lazy"
                decoding="async"
              />
            </a>
            <figcaption>
              <span>02</span>
              <strong>Inspect the report</strong>
              <small>Direct capture of the six-scenario, self-contained HTML artifact.</small>
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
