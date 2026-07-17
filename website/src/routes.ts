export const routes = {
  home: "/",
  docs: "/docs",
  architecture: "/docs/architecture",
  futureWork: "/docs/future-work",
  sources: "/docs/sources",
  adapterKit: "/adapter-kit",
  security: "/security",
  threatModel: "/security/threat-model",
} as const;

export type RoutePath = (typeof routes)[keyof typeof routes];

export function normalizePathname(pathname: string): string {
  if (pathname === "/") return pathname;
  return pathname.replace(/\/+$/, "") || "/";
}

export function isKnownRoute(pathname: string): pathname is RoutePath {
  const normalized = normalizePathname(pathname);
  return Object.values(routes).includes(normalized as RoutePath) || normalized.startsWith("/files/");
}

export function navigate(href: string): void {
  const url = new URL(href, window.location.origin);
  const next = `${url.pathname}${url.search}${url.hash}`;
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;

  if (next !== current) {
    window.history.pushState({}, "", next);
    window.dispatchEvent(new Event("popstate"));
  }

  if (url.hash) {
    window.requestAnimationFrame(() => {
      document.getElementById(url.hash.slice(1))?.scrollIntoView();
    });
  } else {
    window.scrollTo({ top: 0, behavior: "auto" });
  }
}
