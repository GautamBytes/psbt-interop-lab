import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import type { RepositoryResource } from "../pages/repository-resources";
import { MarkdownCodeBlock } from "./MarkdownCodeBlock";

interface RepositoryResourcePageProps {
  resource: RepositoryResource;
}

export function RepositoryResourcePage({ resource }: RepositoryResourcePageProps) {
  return (
    <section className="docs-page repository-resource" aria-labelledby="resource-title">
      <header className="docs-page__intro">
        <div className="page-shell">
          <span className="eyebrow">Repository reference</span>
          <div className="docs-page__intro-row">
            <div>
              <h1 className="docs-page__label" id="resource-title">
                {resource.label}
              </h1>
              <p>{resource.description}</p>
            </div>
            <a className="button button--secondary" href={resource.sourceUrl}>
              View on GitHub <ArrowSquareOut aria-hidden="true" />
            </a>
          </div>
        </div>
      </header>
      <div className="repository-resource__body page-shell">
        <div className="repository-resource__path">
          <span>{resource.kind === "file" ? "File" : "Directory"}</span>
          <code>{resource.sourcePath}</code>
        </div>
        {resource.kind === "file" ? (
          <div className="repository-resource__viewer markdown-body">
            <MarkdownCodeBlock>
              <code className={`language-${resource.language ?? "text"}`}>{resource.content}</code>
            </MarkdownCodeBlock>
          </div>
        ) : (
          <div className="repository-resource__directory">
            <h2>Included source</h2>
            <p>Tracked entry points for the public website and its documentation experience.</p>
            <ul>
              {resource.entries?.map((entry) => (
                <li key={entry}>
                  <code>{entry}</code>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}
