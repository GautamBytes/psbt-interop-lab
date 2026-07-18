import { CheckCircle } from "@phosphor-icons/react/CheckCircle";
import type { Circle } from "@phosphor-icons/react/Circle";
import { Info } from "@phosphor-icons/react/Info";
import { Warning } from "@phosphor-icons/react/Warning";
import { useState } from "react";
import { implementations, reportScenarios, type ScenarioStatus } from "../content";

const statusIcon = {
  pass: CheckCircle,
  finding: Warning,
  supported: Info,
} satisfies Record<ScenarioStatus, typeof Circle>;

export function CompatibilityReport() {
  const [selectedId, setSelectedId] = useState(reportScenarios[1].id);
  const selected =
    reportScenarios.find((scenario) => scenario.id === selectedId) ?? reportScenarios[1];
  const StatusIcon = statusIcon[selected.status];
  const selectedImplementations = implementations.filter((implementation) =>
    selected.implementations.includes(implementation.name),
  );

  return (
    <section className="report-section page-shell" id="matrix" aria-labelledby="report-title">
      <div className="report-console">
        <header className="report-console__header">
          <div>
            <span className="eyebrow">Semantic compatibility report</span>
            <h2 id="report-title">A compatibility report you can act on.</h2>
            <p>See exactly what changed, where it changed, and what evidence to replay.</p>
          </div>
          <span className="network-status">
            Network <strong>regtest</strong>
          </span>
        </header>

        <div className="report-console__body">
          <aside className="scenario-list" aria-label="Report scenarios">
            <span className="scenario-list__title">Scenarios</span>
            {reportScenarios.map((scenario, index) => {
              const Icon = statusIcon[scenario.status];
              return (
                <button
                  key={scenario.id}
                  type="button"
                  className={selected.id === scenario.id ? "is-selected" : ""}
                  aria-pressed={selected.id === scenario.id}
                  onClick={() => setSelectedId(scenario.id)}
                >
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{scenario.shortLabel}</strong>
                  <Icon className={`status-${scenario.status}`} aria-hidden="true" />
                </button>
              );
            })}
            <small>31 bundled scenarios</small>
          </aside>

          <div className="evidence-panel">
            <div className="evidence-panel__summary">
              <div>
                <span className={`status-label status-label--${selected.status}`}>
                  <StatusIcon aria-hidden="true" />
                  {selected.statusLabel}
                </span>
                <h3>{selected.title}</h3>
                <code>{selected.handoff}</code>
              </div>
              <p>{selected.summary}</p>
            </div>

            {selected.classification ? (
              <section className="report-classification" aria-labelledby="classification-title">
                <div className="report-classification__heading">
                  <span>v0.5.4 report output</span>
                  <h4 id="classification-title">Classification</h4>
                </div>
                <dl>
                  <div className="report-classification__field">
                    <dt>Category</dt>
                    <dd>{selected.classification.category}</dd>
                  </div>
                  <div className="report-classification__field">
                    <dt>Severity</dt>
                    <dd className="classification-severity">{selected.classification.severity}</dd>
                  </div>
                  <div className="report-classification__field">
                    <dt>Observed at</dt>
                    <dd>
                      <code>{selected.classification.observedAt}</code>
                    </dd>
                  </div>
                  <div className="report-classification__field">
                    <dt>Repairability</dt>
                    <dd>{selected.classification.repairability}</dd>
                  </div>
                  <div className="report-classification__field">
                    <dt>Confidence</dt>
                    <dd>{selected.classification.confidence}</dd>
                  </div>
                  <div className="report-classification__field report-classification__evidence">
                    <dt>Exact evidence</dt>
                    <dd>
                      <code>{selected.classification.evidence}</code>
                    </dd>
                  </div>
                </dl>
              </section>
            ) : null}

            <ol className="handoff-timeline" aria-label="Implementation handoff">
              {selectedImplementations.map((implementation, index) => (
                <li className="handoff-timeline__item" key={implementation.name}>
                  <span
                    className={`implementation-badge implementation-badge--${implementation.tone}`}
                  >
                    {implementation.short}
                  </span>
                  <span>
                    <strong>{implementation.name}</strong>
                    <small>{implementation.version}</small>
                  </span>
                  {index < selectedImplementations.length - 1 ? <i aria-hidden="true" /> : null}
                </li>
              ))}
            </ol>

            <div className="evidence-table-wrap">
              <table className="evidence-table">
                <thead>
                  <tr>
                    <th>Field</th>
                    <th>Expected</th>
                    <th>Actual</th>
                    <th>Observed implementation</th>
                    <th>Safe next step</th>
                  </tr>
                </thead>
                <tbody>
                  {selected.evidence.map((row) => (
                    <tr key={row.field}>
                      <th scope="row">{row.field}</th>
                      <td className="value-expected">{row.expected}</td>
                      <td
                        className={
                          selected.status === "finding" ? "value-finding" : "value-expected"
                        }
                      >
                        {row.actual}
                      </td>
                      <td>{row.implementation}</td>
                      <td>{row.nextStep}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="replay-command">
              <span>Replay</span>
              <code>{selected.replay}</code>
            </div>
          </div>
        </div>

        <footer className="implementation-strip" id="coverage">
          <span className="implementation-strip__title">Current integrations</span>
          {implementations.map((implementation) => (
            <span className="implementation-strip__item" key={implementation.name}>
              <span className={`implementation-badge implementation-badge--${implementation.tone}`}>
                {implementation.short}
              </span>
              <span>
                <strong>{implementation.name}</strong>
                <small>{implementation.version}</small>
              </span>
            </span>
          ))}
        </footer>
      </div>
    </section>
  );
}
