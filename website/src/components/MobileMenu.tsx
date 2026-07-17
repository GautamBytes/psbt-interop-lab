import { List } from "@phosphor-icons/react/List";
import { X } from "@phosphor-icons/react/X";
import { repositoryUrl } from "../content";

interface MobileMenuProps {
  open: boolean;
  onToggle: () => void;
}

export function MobileMenu({ open, onToggle }: MobileMenuProps) {
  return (
    <div className="mobile-menu">
      <button
        className="icon-button mobile-menu__trigger"
        type="button"
        aria-label={open ? "Close navigation" : "Open navigation"}
        aria-expanded={open}
        aria-controls="mobile-navigation"
        onClick={onToggle}
      >
        {open ? <X aria-hidden="true" /> : <List aria-hidden="true" />}
      </button>
      {open ? (
        <nav id="mobile-navigation" className="mobile-menu__panel" aria-label="Mobile navigation">
          <a href="#matrix" onClick={onToggle}>Matrix</a>
          <a href="#workflow" onClick={onToggle}>How it works</a>
          <a href="#coverage" onClick={onToggle}>Coverage</a>
          <a href={`${repositoryUrl}/blob/main/docs/adapters.md`}>Adapter kit</a>
          <a href={`${repositoryUrl}/blob/main/SECURITY.md`}>Security</a>
        </nav>
      ) : null}
    </div>
  );
}
