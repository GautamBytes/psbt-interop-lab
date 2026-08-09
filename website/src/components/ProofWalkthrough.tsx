import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import silentPaymentsProof from "../../../docs/assets/walkthrough/silent-payments-report.png";
import { releaseFacts } from "../release";
import { SiteLink } from "./SiteLink";
import { ZoomableImage } from "./ZoomableImage";

const facts = [
  {
    label: "Complete run",
    value: `${releaseFacts.walkthroughScenarioCount} / ${releaseFacts.walkthroughScenarioCount} bundled scenarios passed`,
  },
  {
    label: "Coverage",
    value: `${releaseFacts.walkthroughScenarioCount} bundled scenarios across ${releaseFacts.integrationStackCount} integration stacks`,
  },
  {
    label: "Replay",
    value: `${releaseFacts.replayCheckpointCount} checkpoints verified from the same artifact`,
  },
] as const;

export function ProofWalkthrough() {
  return (
    <section className="proof-section" id="proof" aria-labelledby="proof-title">
      <div className="page-shell">
        <header className="proof-heading">
          <div>
            <span className="eyebrow">
              Evidence from the complete {releaseFacts.walkthroughScenarioCount}-scenario matrix | v
              {releaseFacts.walkthroughVersion} capture
            </span>
            <h2 id="proof-title">The complete matrix, one replayable artifact.</h2>
          </div>
          <div>
            <p>
              This complete run executes every bundled workflow against pinned implementations and
              Bitcoin Core on regtest. All {releaseFacts.walkthroughScenarioCount} scenarios passed,{" "}
              {releaseFacts.compatibilityFindingCount} compatibility findings remained visible, and
              the same artifact replay-verified {releaseFacts.replayCheckpointCount} checkpoints.
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
              src={reportProof}
              alt="Complete matrix generated report"
              loading="lazy"
              decoding="async"
            />
            <figcaption>
              <span>01</span>
              <strong>Inspect the v{releaseFacts.walkthroughVersion} report</strong>
              <small>
                Direct capture of the {releaseFacts.walkthroughScenarioCount}-scenario,
                self-contained HTML artifact.
              </small>
            </figcaption>
          </figure>
          <figure>
            <ZoomableImage
              triggerClassName="proof-media__trigger"
              src={silentPaymentsProof}
              alt="Silent Payment conformance report evidence"
              loading="lazy"
              decoding="async"
            />
            <figcaption>
              <span>02</span>
              <strong>Inspect BIP375 conformance</strong>
              <small>
                All 41 official vectors and the native-library divergences stay visible in the same
                report.
              </small>
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
