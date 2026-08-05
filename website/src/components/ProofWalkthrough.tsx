import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import cliProof from "../../../docs/assets/walkthrough/cli-finding-and-replay.png";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import { SiteLink } from "./SiteLink";
import { ZoomableImage } from "./ZoomableImage";

const facts = [
  {
    label: "Complete run",
    value: "47 / 47 bundled scenarios passed",
  },
  {
    label: "Coverage",
    value: "47 bundled scenarios across 9 integration stacks",
  },
  {
    label: "Replay",
    value: "91 checkpoints verified from the same artifact",
  },
] as const;

export function ProofWalkthrough() {
  return (
    <section className="proof-section" id="proof" aria-labelledby="proof-title">
      <div className="page-shell">
        <header className="proof-heading">
          <div>
            <span className="eyebrow">
              Evidence from the complete 47-scenario matrix | v0.8.0 capture, retained in v0.9.0
            </span>
            <h2 id="proof-title">The complete matrix, one replayable artifact.</h2>
          </div>
          <div>
            <p>
              This complete run executes every bundled workflow against pinned implementations and
              Bitcoin Core on regtest. All 47 scenarios passed, one known parser compatibility
              finding remained visible, and the same artifact replay-verified 91 checkpoints.
            </p>
            <SiteLink className="inline-link" href="/docs#walkthrough-verify-the-complete-matrix">
              Open the complete walkthrough <ArrowSquareOut aria-hidden="true" />
            </SiteLink>
          </div>
        </header>

        <div className="proof-media">
          <figure>
            <ZoomableImage
              triggerClassName="proof-media__trigger"
              src={cliProof}
              alt="Complete matrix terminal output"
              loading="lazy"
              decoding="async"
            />
            <figcaption>
              <span>01</span>
              <strong>Run the complete matrix</strong>
              <small>All 47 scenario outcomes and the replay result from one real run.</small>
            </figcaption>
          </figure>

          <figure>
            <ZoomableImage
              triggerClassName="proof-media__trigger"
              src={reportProof}
              alt="Complete matrix generated report"
              loading="lazy"
              decoding="async"
            />
            <figcaption>
              <span>02</span>
              <strong>Inspect the report</strong>
              <small>Direct capture of the 47-scenario, self-contained HTML artifact.</small>
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
