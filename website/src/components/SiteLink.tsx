import type { AnchorHTMLAttributes, MouseEvent } from "react";
import { navigate } from "../routes";

export interface SiteLinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
}

export function SiteLink({ href, onClick, target, ...props }: SiteLinkProps) {
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      target === "_blank" ||
      !href.startsWith("/")
    ) {
      return;
    }

    event.preventDefault();
    navigate(href);
  };

  return <a {...props} href={href} target={target} onClick={handleClick} />;
}
