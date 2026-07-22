import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import cliProof from "../../../docs/assets/walkthrough/cli-finding-and-replay.png";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import { SiteLink } from "./SiteLink";

const facts = [
  {
    label: "Detectors",
    value: "5 / 5 deliberate semantic faults caught",
  },
  {
    label: "Handoff",
    value: "Bitcoin Core to rust-bitcoin to Bitcoin Core",
  },
  {
    label: "Result",
    value: "Finalized, policy accepted, reported, and cleaned up",
  },
] as const;

export function ProofWalkthrough() {
  return (
    <section className="proof-section" id="proof" aria-labelledby="proof-title">
      <div className="page-shell">
        <header className="proof-heading">
          <div>
            <span className="eyebrow">Evidence from a real v0.5.2 quickstart</span>
            <h2 id="proof-title">From one command to a policy-accepted transaction.</h2>
          </div>
          <div>
            <p>
              The bounded first-run proof checks the environment and semantic detectors, completes a
              real signing handoff, writes a self-contained report, and stops Core automatically.
              These captures preserve the original v0.5.2 run; current v0.6.0 reports add sourced
              conformance diagnostics without rewriting historical evidence.
            </p>
            <SiteLink
              className="inline-link"
              href="/docs#walkthrough-verify-your-first-real-handoff"
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
                alt="v0.5.2 quickstart terminal output"
                loading="lazy"
                decoding="async"
              />
            </a>
            <figcaption>
              <span>01</span>
              <strong>Run quickstart</strong>
              <small>
                Actual v0.5.2 output reusing pinned images; only digests and the local path are
                shortened.
              </small>
            </figcaption>
          </figure>

          <figure>
            <a href={reportProof} aria-label="Open full-size generated report">
              <img
                src={reportProof}
                alt="v0.5.2 generated quickstart report"
                loading="lazy"
                decoding="async"
              />
            </a>
            <figcaption>
              <span>02</span>
              <strong>Inspect the report</strong>
              <small>Direct capture of the self-contained HTML artifact from the same run.</small>
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
