import { useEffect, useState } from "react";
import { normalizePathname } from "../routes";

export function useRoute(): string {
  const [pathname, setPathname] = useState(() => normalizePathname(window.location.pathname));

  useEffect(() => {
    const updateRoute = () => setPathname(normalizePathname(window.location.pathname));
    window.addEventListener("popstate", updateRoute);
    return () => window.removeEventListener("popstate", updateRoute);
  }, []);

  return pathname;
}
