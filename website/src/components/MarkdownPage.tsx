import { ArrowSquareOut } from "@phosphor-icons/react/ArrowSquareOut";
import { isValidElement, type ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import cliProof from "../../../docs/assets/walkthrough/cli-finding-and-replay.png";
import reportProof from "../../../docs/assets/walkthrough/compatibility-report.png";
import { repositoryUrl } from "../content";
import { findDocumentBySourcePath, type WebsiteDocument } from "../pages/documents";
import { findRepositoryResourceBySourcePath } from "../pages/repository-resources";
import { MarkdownCodeBlock } from "./MarkdownCodeBlock";
import { MermaidDiagram } from "./MermaidDiagram";
import { SiteLink } from "./SiteLink";

interface MarkdownPageProps {
  document: WebsiteDocument;
}

interface TocItem {
  depth: number;
  label: string;
  id: string;
}

function textFromChildren(children: ReactNode): string {
  if (typeof children === "string" || typeof children === "number") return String(children);
  if (Array.isArray(children)) return children.map(textFromChildren).join("");
  if (isValidElement<{ children?: ReactNode }>(children))
    return textFromChildren(children.props.children);
  return "";
}

function fencedCode(children: ReactNode): { language?: string; value: string } | undefined {
  if (!isValidElement<{ className?: string; children?: ReactNode }>(children)) return undefined;
  const language = children.props.className?.match(/(?:^|\s)language-([^\s]+)/)?.[1];
  return {
    language,
    value: textFromChildren(children.props.children).replace(/\n$/, ""),
  };
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function extractToc(markdown: string): TocItem[] {
  let fenced = false;
  const items: TocItem[] = [];

  for (const line of markdown.split("\n")) {
    if (line.trim().startsWith("```")) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;

    const match = /^(##|###)\s+(.+)$/.exec(line);
    if (match) {
      const label = match[2].replace(/[`*_]/g, "").trim();
      items.push({ depth: match[1].length, label, id: slugify(label) });
    }
  }

  return items;
}

function normalizeRepoPath(baseDir: string, href: string): string {
  const path = href.split("#")[0];
  const parts = `${baseDir}/${path}`.split("/");
  const normalized: string[] = [];

  for (const part of parts) {
    if (!part || part === ".") continue;
    if (part === "..") normalized.pop();
    else normalized.push(part);
  }

  return normalized.join("/");
}

const publicWalkthroughAssetBase =
  "https://raw.githubusercontent.com/GautamBytes/psbt-interop-lab/3b254fe18113fc865d4974607bdfd1b3c74818f5/docs/assets/walkthrough/";

const bundledImages: Readonly<Record<string, string>> = {
  "docs/assets/walkthrough/cli-finding-and-replay.png": cliProof,
  "docs/assets/walkthrough/compatibility-report.png": reportProof,
  [`${publicWalkthroughAssetBase}cli-finding-and-replay.png`]: cliProof,
  [`${publicWalkthroughAssetBase}compatibility-report.png`]: reportProof,
};

export function resolveDocumentImageSrc(src: string | undefined, baseDir: string): string {
  if (!src) return "";
  const bundled = bundledImages[src];
  if (bundled) return bundled;
  if (/^(?:https?:|data:|blob:)/.test(src)) return src;
  const path = normalizeRepoPath(baseDir, src);
  return bundledImages[path] ?? `${repositoryUrl}/raw/main/${path}`;
}

export function resolveDocumentHref(href: string | undefined, baseDir: string): string {
  if (!href || href.startsWith("#") || /^(https?:|mailto:)/.test(href)) return href ?? "#";

  const hash = href.includes("#") ? `#${href.split("#").slice(1).join("#")}` : "";
  const path = normalizeRepoPath(baseDir, href);

  if (bundledImages[path]) return bundledImages[path];

  const internalDocument = findDocumentBySourcePath(path);
  if (internalDocument) return `${internalDocument.route}${hash}`;

  const internalResource = findRepositoryResourceBySourcePath(path);
  if (internalResource) return `${internalResource.route}${hash}`;

  return `${repositoryUrl}/blob/main/${path}${hash}`;
}

function heading(level: 1 | 2 | 3) {
  return function MarkdownHeading({ children }: { children?: ReactNode }) {
    const id = slugify(textFromChildren(children));
    const Tag = `h${level}` as const;
    return <Tag id={id}>{children}</Tag>;
  };
}

export function MarkdownPage({ document }: MarkdownPageProps) {
  const toc = extractToc(document.markdown);
  const components: Components = {
    h1: heading(1),
    h2: heading(2),
    h3: heading(3),
    a: ({ href, children, node, ...props }) => {
      void node;
      const resolved = resolveDocumentHref(href, document.baseDir);
      return resolved.startsWith("/") ? (
        <SiteLink {...props} href={resolved}>
          {children}
        </SiteLink>
      ) : (
        <a {...props} href={resolved}>
          {children}
        </a>
      );
    },
    img: ({ src, alt, node, ...props }) => {
      void node;
      const resolved = resolveDocumentImageSrc(src, document.baseDir);
      const label = alt || "Documentation image";
      return (
        <a className="markdown-proof-image" href={resolved} aria-label={`Open full-size ${label}`}>
          <img {...props} src={resolved} alt={alt ?? ""} loading="lazy" decoding="async" />
        </a>
      );
    },
    table: ({ children, node, ...props }) => {
      void node;
      return (
        <div className="markdown-table-wrap">
          <table {...props}>{children}</table>
        </div>
      );
    },
    pre: ({ children, node }) => {
      void node;
      const code = fencedCode(children);
      if (code?.language === "mermaid") {
        return <MermaidDiagram definition={code.value} label={`${document.label} diagram`} />;
      }
      return <MarkdownCodeBlock>{children}</MarkdownCodeBlock>;
    },
  };

  return (
    <section className="docs-page" aria-labelledby="document-title">
      <header className="docs-page__intro">
        <div className="page-shell">
          <span className="eyebrow">Project knowledge base</span>
          <div className="docs-page__intro-row">
            <div>
              <p className="docs-page__label">{document.label}</p>
              <p>{document.description}</p>
            </div>
            <a className="button button--secondary" href={document.sourceUrl}>
              View source <ArrowSquareOut aria-hidden="true" />
            </a>
          </div>
        </div>
      </header>
      <div className="docs-layout page-shell">
        <aside className="docs-toc" aria-label={`${document.label} sections`}>
          <span>On this page</span>
          <nav>
            {toc.map((item) => (
              <a
                className={item.depth === 3 ? "is-nested" : ""}
                href={`#${item.id}`}
                key={`${item.id}-${item.depth}`}
              >
                {item.label}
              </a>
            ))}
          </nav>
          <code>{document.sourcePath}</code>
        </aside>
        <article className="markdown-body">
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
            {document.markdown}
          </ReactMarkdown>
        </article>
      </div>
    </section>
  );
}
