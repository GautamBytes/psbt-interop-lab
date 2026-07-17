import { List } from "@phosphor-icons/react/List";
import { X } from "@phosphor-icons/react/X";
import { routes } from "../routes";
import { SiteLink } from "./SiteLink";

interface MobileMenuProps {
  open: boolean;
  onToggle: () => void;
  pathname: string;
}

export function MobileMenu({ open, onToggle, pathname }: MobileMenuProps) {
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
          <SiteLink
            href={routes.docs}
            aria-current={
              pathname.startsWith("/docs") || pathname.startsWith("/files/") ? "page" : undefined
            }
            onClick={onToggle}
          >
            Docs
          </SiteLink>
          <SiteLink href="/#matrix" onClick={onToggle}>
            Matrix
          </SiteLink>
          <SiteLink href="/#workflow" onClick={onToggle}>
            How it works
          </SiteLink>
          <SiteLink href="/#coverage" onClick={onToggle}>
            Coverage
          </SiteLink>
          <SiteLink
            href={routes.adapterKit}
            aria-current={pathname === routes.adapterKit ? "page" : undefined}
            onClick={onToggle}
          >
            Adapter kit
          </SiteLink>
          <SiteLink
            href={routes.security}
            aria-current={pathname.startsWith("/security") ? "page" : undefined}
            onClick={onToggle}
          >
            Security
          </SiteLink>
        </nav>
      ) : null}
    </div>
  );
}
