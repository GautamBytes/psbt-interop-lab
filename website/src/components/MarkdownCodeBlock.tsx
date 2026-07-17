import { Check } from "@phosphor-icons/react/Check";
import { Copy } from "@phosphor-icons/react/Copy";
import { isValidElement, type ReactNode, useEffect, useRef, useState } from "react";

interface MarkdownCodeBlockProps {
  children: ReactNode;
}

function textContent(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return textContent(node.props.children);
  return "";
}

export function MarkdownCodeBlock({ children }: MarkdownCodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<number | undefined>(undefined);
  const value = textContent(children).replace(/\n$/, "");

  useEffect(() => () => window.clearTimeout(timerRef.current), []);

  const copyCode = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="markdown-code-block">
      <pre>{children}</pre>
      <button
        className="markdown-code-block__copy"
        type="button"
        aria-label="Copy code block"
        title={copied ? "Copied" : "Copy"}
        onClick={copyCode}
      >
        {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      </button>
      <span className="sr-only" aria-live="polite">
        {copied ? "Code block copied" : ""}
      </span>
    </div>
  );
}
