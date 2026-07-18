import { useCallback, useEffect, useState } from "react";
import { CompatibilityReport } from "./components/CompatibilityReport";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { MarkdownPage } from "./components/MarkdownPage";
import { RepositoryResourcePage } from "./components/RepositoryResourcePage";
import { SearchDialog } from "./components/SearchDialog";
import { Sections } from "./components/Sections";
import { SiteLink } from "./components/SiteLink";
import { repositoryUrl } from "./content";
import { useRoute } from "./hooks/useRoute";
import { findDocument } from "./pages/documents";
import { NotFoundPage } from "./pages/NotFoundPage";
import { findRepositoryResource } from "./pages/repository-resources";
import { routes } from "./routes";

type Theme = "dark" | "light";

function initialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = window.localStorage.getItem("psbt-lab-theme");
  if (stored === "dark" || stored === "light") return stored;
  return "dark";
}

export function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [searchOpen, setSearchOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const pathname = useRoute();
  const activeDocument = findDocument(pathname);
  const activeResource = findRepositoryResource(pathname);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("psbt-lab-theme", theme);
  }, [theme]);

  const closeSearch = useCallback(() => setSearchOpen(false), []);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
      }
    };
    document.addEventListener("keydown", handleShortcut);
    return () => document.removeEventListener("keydown", handleShortcut);
  }, []);

  useEffect(() => {
    setMenuOpen(false);
    const title =
      activeDocument?.label ??
      activeResource?.label ??
      (pathname === routes.home ? "PSBT Interop Lab" : "Page not found");
    window.document.title = title === "PSBT Interop Lab" ? title : `${title} | PSBT Interop Lab`;
  }, [activeDocument, activeResource, pathname]);

  const page =
    pathname === routes.home ? (
      <>
        <Hero />
        <CompatibilityReport />
        <Sections />
      </>
    ) : activeDocument ? (
      <MarkdownPage document={activeDocument} />
    ) : activeResource ? (
      <RepositoryResourcePage resource={activeResource} />
    ) : (
      <NotFoundPage />
    );

  return (
    <div className="site-frame">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <Header
        pathname={pathname}
        theme={theme}
        menuOpen={menuOpen}
        onMenuToggle={() => setMenuOpen((open) => !open)}
        onSearchOpen={() => setSearchOpen(true)}
        onThemeToggle={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
      />
      <main id="main-content">{page}</main>
      <footer className="site-footer">
        <div className="page-shell">
          <span>PSBT Interop Lab 0.5.1</span>
          <span>MIT licensed</span>
          <SiteLink href={routes.security}>Security</SiteLink>
          <a href={repositoryUrl}>GitHub</a>
        </div>
      </footer>
      <SearchDialog open={searchOpen} onClose={closeSearch} />
    </div>
  );
}
