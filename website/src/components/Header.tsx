import { GithubLogo } from "@phosphor-icons/react/GithubLogo";
import { MagnifyingGlass } from "@phosphor-icons/react/MagnifyingGlass";
import { repositoryUrl } from "../content";
import { Brand } from "./Brand";
import { MobileMenu } from "./MobileMenu";
import { ThemeToggle } from "./ThemeToggle";

interface HeaderProps {
  theme: "dark" | "light";
  menuOpen: boolean;
  onMenuToggle: () => void;
  onSearchOpen: () => void;
  onThemeToggle: () => void;
}

export function Header({
  theme,
  menuOpen,
  onMenuToggle,
  onSearchOpen,
  onThemeToggle,
}: HeaderProps) {
  return (
    <header className="site-header">
      <div className="site-header__inner">
        <a className="site-header__brand" href="#top" aria-label="PSBT Interop Lab home">
          <Brand />
        </a>
        <nav className="desktop-nav" aria-label="Primary navigation">
          <a href={`${repositoryUrl}#quick-start`}>Docs</a>
          <a href="#matrix">Matrix</a>
          <a href={`${repositoryUrl}/blob/main/docs/adapters.md`}>Adapter kit</a>
          <a href={`${repositoryUrl}/blob/main/SECURITY.md`}>Security</a>
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
          <MobileMenu open={menuOpen} onToggle={onMenuToggle} />
        </div>
      </div>
    </header>
  );
}
