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
            <small>24 bundled scenarios</small>
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

            <ol className="handoff-timeline" aria-label="Implementation handoff">
              {implementations.map((implementation, index) => (
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
                  {index < implementations.length - 1 ? <i aria-hidden="true" /> : null}
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
                    <th>Likely implementation</th>
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
