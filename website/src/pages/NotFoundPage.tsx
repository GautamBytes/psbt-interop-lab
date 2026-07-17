import { SiteLink } from "../components/SiteLink";
import { routes } from "../routes";

export function NotFoundPage() {
  return (
    <section className="not-found page-shell">
      <span className="eyebrow">404</span>
      <h1>Page not found</h1>
      <p>The page does not exist in the PSBT Interop Lab website.</p>
      <SiteLink className="button button--primary" href={routes.home}>Return home</SiteLink>
    </section>
  );
}
