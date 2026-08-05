import { ArrowsOutSimple } from "@phosphor-icons/react/ArrowsOutSimple";
import { X } from "@phosphor-icons/react/X";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useModalFocus } from "../hooks/useModalFocus";
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
  const [open, setOpen] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const close = useCallback(() => setOpen(false), []);

  useModalFocus({ open, containerRef: dialogRef, initialFocusRef: closeRef, onDismiss: close });

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
        <>
          <figcaption className="mermaid-diagram__toolbar">
            <span>System map</span>
            <button
              type="button"
              aria-label={`Open ${label} full screen`}
              onClick={() => setOpen(true)}
            >
              <ArrowsOutSimple aria-hidden="true" weight="bold" />
              Full screen
            </button>
          </figcaption>
          {!open ? (
            <div
              className="mermaid-diagram__canvas"
              role="img"
              aria-label={label}
              // biome-ignore lint/security/noDangerouslySetInnerHtml: Mermaid renders trusted repository-owned diagrams with securityLevel set to strict.
              dangerouslySetInnerHTML={{ __html: svg }}
            />
          ) : null}
          {open
            ? createPortal(
                // biome-ignore lint/a11y/noStaticElementInteractions: The backdrop supplements the accessible close button and Escape key.
                <div
                  className="diagram-preview-backdrop"
                  role="presentation"
                  onClick={(event) => {
                    if (event.target === event.currentTarget) close();
                  }}
                >
                  <section
                    ref={dialogRef}
                    className="diagram-preview-dialog"
                    role="dialog"
                    aria-modal="true"
                    aria-label={`${label} full-screen view`}
                  >
                    <header className="diagram-preview-header">
                      <span>{label}</span>
                      <button
                        ref={closeRef}
                        type="button"
                        aria-label="Close diagram preview"
                        onClick={close}
                      >
                        <X aria-hidden="true" weight="bold" />
                      </button>
                    </header>
                    <div
                      className="diagram-preview-canvas"
                      role="img"
                      aria-label={`${label} full screen`}
                      // biome-ignore lint/a11y/noNoninteractiveTabindex: The focusable overflow region lets keyboard users pan the full-size diagram.
                      tabIndex={0}
                      // biome-ignore lint/security/noDangerouslySetInnerHtml: Reuses Mermaid's trusted strict-mode SVG in the reading view.
                      dangerouslySetInnerHTML={{ __html: svg }}
                    />
                  </section>
                </div>,
                document.body,
              )
            : null}
        </>
      ) : (
        <div className="mermaid-diagram__loading" role="status">
          Rendering diagram...
        </div>
      )}
    </figure>
  );
}
