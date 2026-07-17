export const routes = {
  home: "/",
  docs: "/docs",
  adapterKit: "/adapter-kit",
  security: "/security",
} as const;

export type RoutePath = (typeof routes)[keyof typeof routes];

export function normalizePathname(pathname: string): string {
  if (pathname === "/") return pathname;
  return pathname.replace(/\/+$/, "") || "/";
}

export function isKnownRoute(pathname: string): pathname is RoutePath {
  return Object.values(routes).includes(normalizePathname(pathname) as RoutePath);
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
