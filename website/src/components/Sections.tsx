import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import { BracketsCurly } from "@phosphor-icons/react/BracketsCurly";
import { CheckCircle } from "@phosphor-icons/react/CheckCircle";
import { FileLock } from "@phosphor-icons/react/FileLock";
import { Fingerprint } from "@phosphor-icons/react/Fingerprint";
import { GithubLogo } from "@phosphor-icons/react/GithubLogo";
import { HardDrives } from "@phosphor-icons/react/HardDrives";
import { Package } from "@phosphor-icons/react/Package";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { TerminalWindow } from "@phosphor-icons/react/TerminalWindow";
import { npmUrl, repositoryUrl, workflowSteps } from "../content";
import { routes } from "../routes";
import { SiteLink } from "./SiteLink";

const coverage = [
  "P2WPKH, nested SegWit, P2WSH, and Taproot fixtures",
  "Signing, combining, finalization, and policy acceptance",
  "Unknown and proprietary metadata preservation",
  "All official BIP370 valid and invalid vectors",
  "Transaction intent, RBF, locktime, sighash, and derivations",
  "Malformed native-parser rejection without crashes",
] as const;

export function Sections() {
  return (
    <>
      <section
        className="content-section workflow-section"
        id="workflow"
        aria-labelledby="workflow-title"
      >
        <div className="page-shell">
          <header className="section-heading">
            <span className="eyebrow">From handoff to evidence</span>
            <h2 id="workflow-title">Test the workflow, not just one library.</h2>
            <p>
              PSBT was designed for different tools to perform different roles. The lab checks the
              boundaries between those roles, where subtle failures actually appear.
            </p>
          </header>
          <div className="workflow-steps">
            {workflowSteps.map((step, index) => (
              <article key={step.number}>
                <span className="workflow-step__number">{step.number}</span>
                <div>
                  <h3>{step.title}</h3>
                  <p>{step.body}</p>
                </div>
                {index < workflowSteps.length - 1 ? <ArrowRight aria-hidden="true" /> : null}
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="content-section coverage-section" aria-labelledby="coverage-title">
        <div className="page-shell coverage-layout">
          <div>
            <span className="eyebrow">Coverage that earns trust</span>
            <h2 id="coverage-title">Real implementations. Real transitions.</h2>
            <p>
              Every supported cell runs against a pinned implementation. Unsupported capabilities
              remain visible instead of turning into false passes.
            </p>
            <SiteLink className="inline-link" href="/docs#current-coverage">
              Read the full scenario list <ArrowSquareOut aria-hidden="true" />
            </SiteLink>
          </div>
          <ul className="coverage-list">
            {coverage.map((item) => (
              <li key={item}>
                <CheckCircle aria-hidden="true" weight="fill" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section
        className="content-section safety-section"
        id="security"
        aria-labelledby="safety-title"
      >
        <div className="page-shell">
          <header className="section-heading section-heading--compact">
            <span className="eyebrow">A deliberately narrow safety boundary</span>
            <h2 id="safety-title">Built to test signers, never become one.</h2>
          </header>
          <div className="safety-grid">
            <article>
              <ShieldCheck aria-hidden="true" />
              <h3>Regtest only</h3>
              <p>No mainnet mode, no broadcast path, and no keys with economic value.</p>
            </article>
            <article>
              <Fingerprint aria-hidden="true" />
              <h3>Intent committed</h3>
              <p>Signers receive a run-scoped commitment to the exact unsigned transaction.</p>
            </article>
            <article>
              <HardDrives aria-hidden="true" />
              <h3>Local artifacts</h3>
              <p>Raw checkpoints stay private on disk; reports redact common secret material.</p>
            </article>
            <article>
              <FileLock aria-hidden="true" />
              <h3>Isolated adapters</h3>
              <p>No network, read-only roots, dropped capabilities, and bounded processes.</p>
            </article>
          </div>
        </div>
      </section>

      <section
        className="content-section adapter-section"
        id="adapters"
        aria-labelledby="adapter-title"
      >
        <div className="page-shell adapter-layout">
          <div>
            <span className="eyebrow">Bring your implementation</span>
            <h2 id="adapter-title">Join the matrix without forking the lab.</h2>
            <p>
              A strict local JSONL adapter protocol lets maintainers test another wallet or library
              against the bundled scenarios and semantic invariants.
            </p>
            <div className="adapter-actions">
              <SiteLink className="button button--primary" href={routes.adapterKit}>
                <BracketsCurly aria-hidden="true" />
                Build an adapter
              </SiteLink>
              <SiteLink
                className="button button--text"
                href="/files/src/conformance/adapter-manifest.schema.json"
              >
                View the schema <ArrowSquareOut aria-hidden="true" />
              </SiteLink>
            </div>
          </div>
          <section className="adapter-terminal" aria-label="Adapter command example">
            <div className="adapter-terminal__bar">
              <span />
              <span />
              <span />
              <small>adapter-check</small>
            </div>
            <pre>
              <code>
                <span>$</span> psbt-lab adapter check ./adapters.json{"\n"}
                {"\n"}
                <b>PASS</b> manifest schema{"\n"}
                <b>PASS</b> implementation identity{"\n"}
                <b>PASS</b> malformed parser behavior{"\n"}
                <b>PASS</b> semantic roundtrip preservation{"\n"}
                {"\n"}
                <em>Adapter is ready for the matrix.</em>
              </code>
            </pre>
          </section>
        </div>
      </section>

      <section className="final-cta" aria-labelledby="cta-title">
        <div className="page-shell">
          <Package aria-hidden="true" weight="duotone" />
          <h2 id="cta-title">Run the same PSBT through every handoff.</h2>
          <p>Open source, MIT licensed, and available now as version 0.5.0.</p>
          <div>
            <a className="button button--primary" href={npmUrl}>
              <TerminalWindow aria-hidden="true" />
              Install from npm
            </a>
            <a className="button button--secondary" href={repositoryUrl}>
              <GithubLogo aria-hidden="true" />
              View source
            </a>
          </div>
        </div>
      </section>
    </>
  );
}
