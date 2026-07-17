import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { MagnifyingGlass } from "@phosphor-icons/react/MagnifyingGlass";
import { X } from "@phosphor-icons/react/X";
import { useEffect, useMemo, useRef, useState } from "react";
import { docLinks } from "../content";
import { SiteLink } from "./SiteLink";

interface SearchDialogProps {
  open: boolean;
  onClose: () => void;
}

export function SearchDialog({ open, onClose }: SearchDialogProps) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    const frame = window.requestAnimationFrame(() => inputRef.current?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handleKeyDown);
    document.body.classList.add("dialog-open");
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.classList.remove("dialog-open");
    };
  }, [open, onClose]);

  const matches = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return docLinks;
    return docLinks.filter((link) =>
      `${link.label} ${link.detail}`.toLowerCase().includes(normalized),
    );
  }, [query]);

  if (!open) return null;

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="search-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="search-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="search-dialog__header">
          <div>
            <span className="eyebrow">Project search</span>
            <h2 id="search-title">Find documentation</h2>
          </div>
          <button className="icon-button" type="button" aria-label="Close search" onClick={onClose}>
            <X aria-hidden="true" />
          </button>
        </div>
        <label className="search-dialog__input">
          <MagnifyingGlass aria-hidden="true" />
          <span className="sr-only">Search documentation</span>
          <input
            ref={inputRef}
            type="search"
            value={query}
            placeholder="Search quick start, adapters, security..."
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <div className="search-dialog__results" aria-live="polite">
          {matches.length ? (
            matches.map((link) => (
              <SiteLink key={link.label} href={link.href} onClick={onClose}>
                <span>
                  <strong>{link.label}</strong>
                  <small>{link.detail}</small>
                </span>
                <ArrowUpRight aria-hidden="true" />
              </SiteLink>
            ))
          ) : (
            <p className="search-dialog__empty">No matching documentation.</p>
          )}
        </div>
      </section>
    </div>
  );
}
