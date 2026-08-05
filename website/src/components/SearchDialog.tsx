import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { MagnifyingGlass } from "@phosphor-icons/react/MagnifyingGlass";
import { X } from "@phosphor-icons/react/X";
import { useEffect, useMemo, useRef, useState } from "react";
import { docLinks } from "../content";
import { useModalFocus } from "../hooks/useModalFocus";
import { documents } from "../pages/documents";
import { SiteLink } from "./SiteLink";

interface SearchDialogProps {
  open: boolean;
  onClose: () => void;
}

export function SearchDialog({ open, onClose }: SearchDialogProps) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLElement>(null);

  useModalFocus({ open, containerRef: dialogRef, initialFocusRef: inputRef, onDismiss: onClose });

  useEffect(() => {
    if (!open) return;
    setQuery("");
  }, [open]);

  const matches = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return docLinks;
    const navigationMatches = docLinks.filter((link) =>
      `${link.label} ${link.detail}`.toLowerCase().includes(normalized),
    );
    const documentMatches = documents
      .filter((document) =>
        `${document.label} ${document.description} ${document.markdown}`
          .toLowerCase()
          .includes(normalized),
      )
      .map((document) => ({
        label: document.label,
        detail: document.description,
        href: document.route,
      }));

    return [...navigationMatches, ...documentMatches].filter(
      (match, index, all) => all.findIndex((candidate) => candidate.href === match.href) === index,
    );
  }, [query]);

  if (!open) return null;

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: The backdrop is pointer-only; Escape and the close button provide keyboard dismissal.
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
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
