import { useEffect, useId, useState } from "react";
import { MarkdownCodeBlock } from "./MarkdownCodeBlock";

type MermaidApi = typeof import("mermaid")["default"];

let mermaidPromise: Promise<MermaidApi> | undefined;

function loadMermaid(): Promise<MermaidApi> {
  mermaidPromise ??= import("mermaid").then(({ default: mermaid }) => {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: {
        background: "#07090b",
        primaryColor: "#14191e",
        primaryTextColor: "#f4f5f6",
        primaryBorderColor: "#f7931a",
        secondaryColor: "#101418",
        tertiaryColor: "#0b0e11",
        lineColor: "#7d8790",
        edgeLabelBackground: "#0b0e11",
        fontFamily: "Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
      },
      flowchart: {
        useMaxWidth: true,
      },
    });
    return mermaid;
  });

  return mermaidPromise;
}

interface MermaidDiagramProps {
  definition: string;
  label: string;
}

export function MermaidDiagram({ definition, label }: MermaidDiagramProps) {
  const reactId = useId();
  const diagramId = `mermaid-${reactId.replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const [svg, setSvg] = useState<string>();
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSvg(undefined);
    setFailed(false);

    void loadMermaid()
      .then((mermaid) => mermaid.render(diagramId, definition))
      .then(({ svg: renderedSvg }) => {
        if (!cancelled) setSvg(renderedSvg);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });

    return () => {
      cancelled = true;
      document.getElementById(`d${diagramId}`)?.remove();
    };
  }, [definition, diagramId]);

  if (failed) {
    return (
      <div className="mermaid-diagram mermaid-diagram--error" role="alert">
        <p>The diagram could not be rendered. Its source is shown below.</p>
        <MarkdownCodeBlock>
          <code>{definition}</code>
        </MarkdownCodeBlock>
      </div>
    );
  }

  return (
    <figure className="mermaid-diagram" aria-busy={!svg}>
      {svg ? (
        <div
          className="mermaid-diagram__canvas"
          role="img"
          aria-label={label}
          // biome-ignore lint/security/noDangerouslySetInnerHtml: Mermaid renders trusted repository-owned diagrams with securityLevel set to strict.
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      ) : (
        <div className="mermaid-diagram__loading" role="status">
          Rendering diagram...
        </div>
      )}
    </figure>
  );
}
