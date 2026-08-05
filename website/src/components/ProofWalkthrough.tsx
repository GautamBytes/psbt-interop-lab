import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import musig2Proof from "../../../docs/assets/walkthrough/musig2-report.png";
import { releaseFacts } from "../release";
import { SiteLink } from "./SiteLink";
import { ZoomableImage } from "./ZoomableImage";

const facts = [
  {
    label: "Complete run",
    value: `${releaseFacts.scenarioCount} / ${releaseFacts.scenarioCount} bundled scenarios passed`,
  },
  {
    label: "Coverage",
    value: `${releaseFacts.scenarioCount} bundled scenarios across ${releaseFacts.integrationStackCount} integration stacks`,
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
              Evidence from the complete {releaseFacts.scenarioCount}-scenario matrix | v
              {releaseFacts.version} capture
            </span>
            <h2 id="proof-title">The complete matrix, one replayable artifact.</h2>
          </div>
          <div>
            <p>
              This complete run executes every bundled workflow against pinned implementations and
              Bitcoin Core on regtest. All {releaseFacts.scenarioCount} scenarios passed, one known
              parser compatibility finding remained visible, and the same artifact replay-verified{" "}
              {releaseFacts.replayCheckpointCount} checkpoints.
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
              <strong>Inspect the v{releaseFacts.version} report</strong>
              <small>
                Direct capture of the {releaseFacts.scenarioCount}-scenario, self-contained HTML
                artifact.
              </small>
            </figcaption>
          </figure>
          <figure>
            <ZoomableImage
              triggerClassName="proof-media__trigger"
              src={musig2Proof}
              alt="BIP373 MuSig2 report evidence"
              loading="lazy"
              decoding="async"
            />
            <figcaption>
              <span>02</span>
              <strong>Trace independent MuSig2 signers</strong>
              <small>
                The expected nonce-reuse refusal appears as a red negative canary inside the passed
                scenario.
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
