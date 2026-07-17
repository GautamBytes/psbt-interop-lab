import { useCallback, useEffect, useState } from "react";
import { CompatibilityReport } from "./components/CompatibilityReport";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { SearchDialog } from "./components/SearchDialog";
import { Sections } from "./components/Sections";
import { repositoryUrl } from "./content";

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

  return (
    <div className="site-frame">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header
        theme={theme}
        menuOpen={menuOpen}
        onMenuToggle={() => setMenuOpen((open) => !open)}
        onSearchOpen={() => setSearchOpen(true)}
        onThemeToggle={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
      />
      <main id="main-content">
        <Hero />
        <CompatibilityReport />
        <Sections />
      </main>
      <footer className="site-footer">
        <div className="page-shell">
          <span>PSBT Interop Lab 0.4.0</span>
          <span>MIT licensed</span>
          <a href={`${repositoryUrl}/blob/main/SECURITY.md`}>Security</a>
          <a href={repositoryUrl}>GitHub</a>
        </div>
      </footer>
      <SearchDialog open={searchOpen} onClose={closeSearch} />
    </div>
  );
}
