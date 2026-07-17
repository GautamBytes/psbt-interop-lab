import { GithubLogo } from "@phosphor-icons/react/GithubLogo";
import { MagnifyingGlass } from "@phosphor-icons/react/MagnifyingGlass";
import { repositoryUrl } from "../content";
import { routes } from "../routes";
import { Brand } from "./Brand";
import { MobileMenu } from "./MobileMenu";
import { SiteLink } from "./SiteLink";
import { ThemeToggle } from "./ThemeToggle";

interface HeaderProps {
  pathname: string;
  theme: "dark" | "light";
  menuOpen: boolean;
  onMenuToggle: () => void;
  onSearchOpen: () => void;
  onThemeToggle: () => void;
}

export function Header({
  pathname,
  theme,
  menuOpen,
  onMenuToggle,
  onSearchOpen,
  onThemeToggle,
}: HeaderProps) {
  return (
    <header className="site-header">
      <div className="site-header__inner">
        <SiteLink className="site-header__brand" href={routes.home} aria-label="PSBT Interop Lab home">
          <Brand />
        </SiteLink>
        <nav className="desktop-nav" aria-label="Primary navigation">
          <SiteLink href={routes.docs} aria-current={pathname.startsWith("/docs") ? "page" : undefined}>Docs</SiteLink>
          <SiteLink href="/#matrix">Matrix</SiteLink>
          <SiteLink href={routes.adapterKit} aria-current={pathname === routes.adapterKit ? "page" : undefined}>Adapter kit</SiteLink>
          <SiteLink href={routes.security} aria-current={pathname.startsWith("/security") ? "page" : undefined}>Security</SiteLink>
        </nav>
        <div className="site-header__actions">
          <button
            className="search-trigger"
            type="button"
            aria-label="Search documentation"
            onClick={onSearchOpen}
          >
            <MagnifyingGlass aria-hidden="true" />
            <span>Search docs...</span>
            <kbd>Cmd K</kbd>
          </button>
          <a className="icon-button" href={repositoryUrl} aria-label="View project on GitHub">
            <GithubLogo aria-hidden="true" weight="fill" />
          </a>
          <ThemeToggle theme={theme} onToggle={onThemeToggle} />
          <MobileMenu open={menuOpen} onToggle={onMenuToggle} pathname={pathname} />
        </div>
      </div>
    </header>
  );
}
