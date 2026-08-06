import { useCallback, useEffect, useState } from "react";
import { AudiencePaths } from "./components/AudiencePaths";
import { CompatibilityReport } from "./components/CompatibilityReport";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { MarkdownPage } from "./components/MarkdownPage";
import { ProofWalkthrough } from "./components/ProofWalkthrough";
import { RepositoryResourcePage } from "./components/RepositoryResourcePage";
import { SearchDialog } from "./components/SearchDialog";
import { Sections } from "./components/Sections";
import { useRoute } from "./hooks/useRoute";
import { findDocument } from "./pages/documents";
import { NotFoundPage } from "./pages/NotFoundPage";
import { findRepositoryResource } from "./pages/repository-resources";
import { releaseFacts } from "./release";
import { routes } from "./routes";

type Theme = "dark" | "light";

const homeDescription =
  "Find PSBT interoperability failures across real Bitcoin libraries with deterministic, replayable tests.";

function setMeta(selector: string, attribute: "name" | "property", key: string, content: string) {
  let element = document.head.querySelector<HTMLMetaElement>(selector);
  if (!element) {
    element = document.createElement("meta");
    element.setAttribute(attribute, key);
    document.head.append(element);
  }
  element.content = content;
}

function initialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = window.localStorage.getItem("psbt-lab-theme");
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
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
  }, [theme]);

  useEffect(() => {
    if (window.localStorage.getItem("psbt-lab-theme")) return;
    const preference = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!preference) return;
    const followSystemTheme = (event: MediaQueryListEvent) => {
      if (window.localStorage.getItem("psbt-lab-theme")) return;
      setTheme(event.matches ? "light" : "dark");
    };
    preference.addEventListener?.("change", followSystemTheme);
    return () => preference.removeEventListener?.("change", followSystemTheme);
  }, []);

  const closeSearch = useCallback(() => setSearchOpen(false), []);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (menuOpen || document.body.classList.contains("dialog-open")) return;
        setSearchOpen(true);
      }
    };
    document.addEventListener("keydown", handleShortcut);
    return () => document.removeEventListener("keydown", handleShortcut);
  }, [menuOpen]);

  useEffect(() => {
    setMenuOpen(false);
    const title =
      activeDocument?.label ??
      activeResource?.label ??
      (pathname === routes.home ? "PSBT Interop Lab" : "Page not found");
    const pageTitle = title === "PSBT Interop Lab" ? title : `${title} | PSBT Interop Lab`;
    const description =
      activeDocument?.description ??
      activeResource?.description ??
      (pathname === routes.home
        ? homeDescription
        : "The requested PSBT Interop Lab page was not found.");
    window.document.title = pageTitle;
    setMeta('meta[name="description"]', "name", "description", description);
  }, [activeDocument, activeResource, pathname]);

  const page =
    pathname === routes.home ? (
      <>
        <Hero />
        <AudiencePaths />
        <CompatibilityReport />
        <ProofWalkthrough />
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
        onThemeToggle={() =>
          setTheme((current) => {
            const next = current === "dark" ? "light" : "dark";
            window.localStorage.setItem("psbt-lab-theme", next);
            return next;
          })
        }
      />
      <main id="main-content">{page}</main>
      <footer className="site-footer">
        <div className="page-shell">
          <div className="site-footer__meta">
            <span>PSBT Interop Lab {releaseFacts.version}</span>
            <span>MIT licensed</span>
          </div>
          <nav aria-label="Gautam Manchandani profiles" className="site-footer__profiles">
            <span>Reach out</span>
            <a href="https://x.com/GautamM96" rel="noreferrer noopener" target="_blank">
              X <span aria-hidden="true">↗</span>
            </a>
            <a
              href="https://www.linkedin.com/in/gautam-manchandani/"
              rel="noreferrer noopener"
              target="_blank"
            >
              LinkedIn <span aria-hidden="true">↗</span>
            </a>
            <a href="https://github.com/GautamBytes" rel="noreferrer noopener" target="_blank">
              GitHub <span aria-hidden="true">↗</span>
            </a>
          </nav>
        </div>
      </footer>
      <SearchDialog open={searchOpen} onClose={closeSearch} />
    </div>
  );
}
