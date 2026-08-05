import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import { FileText } from "@phosphor-icons/react/FileText";
import type { RepositoryResource } from "../pages/repository-resources";
import { MarkdownCodeBlock } from "./MarkdownCodeBlock";

interface RepositoryResourcePageProps {
  resource: RepositoryResource;
}

export function RepositoryResourcePage({ resource }: RepositoryResourcePageProps) {
  return (
    <section
      className="docs-page docs-page--reference repository-resource"
      aria-labelledby="resource-title"
    >
      <header className="docs-page__intro">
        <div className="page-shell">
          <div className="docs-page__intro-row">
            <div className="docs-page__mark">
              <FileText aria-hidden="true" weight="duotone" />
            </div>
            <div className="docs-page__intro-copy">
              <span className="eyebrow">Repository reference</span>
              <h1 className="docs-page__label" id="resource-title">
                {resource.label}
              </h1>
              <p>{resource.description}</p>
            </div>
            <a className="button button--secondary" href={resource.sourceUrl}>
              View on GitHub <ArrowSquareOut aria-hidden="true" />
            </a>
          </div>
          <section
            className="docs-page__overview docs-page__overview--resource"
            aria-label={`${resource.label} overview`}
          >
            <dl className="docs-page__overview-list">
              <div>
                <dt>Document</dt>
                <dd>Repository {resource.kind}</dd>
              </div>
              <div>
                <dt>Repository source</dt>
                <dd>
                  <code>{resource.sourcePath}</code>
                </dd>
              </div>
            </dl>
          </section>
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
