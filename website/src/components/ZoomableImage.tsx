import { X } from "@phosphor-icons/react/X";
import { type ImgHTMLAttributes, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface ZoomableImageProps extends Omit<ImgHTMLAttributes<HTMLImageElement>, "alt" | "src"> {
  alt: string;
  src: string;
  triggerClassName?: string;
}

export function ZoomableImage({ alt, src, triggerClassName, ...imageProps }: ZoomableImageProps) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  const close = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (!open) return;

    const frame = window.requestAnimationFrame(() => closeRef.current?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };

    document.addEventListener("keydown", handleKeyDown);
    document.body.classList.add("dialog-open");

    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.classList.remove("dialog-open");
      triggerRef.current?.focus();
    };
  }, [close, open]);

  return (
    <>
      <button
        ref={triggerRef}
        className={["image-preview-trigger", triggerClassName].filter(Boolean).join(" ")}
        type="button"
        aria-label={`Open full-size ${alt}`}
        onClick={() => setOpen(true)}
      >
        <img {...imageProps} src={src} alt={alt} />
      </button>

      {open
        ? createPortal(
            // biome-ignore lint/a11y/noStaticElementInteractions: The backdrop supplements the accessible close button and Escape key.
            <div
              className="image-preview-backdrop"
              role="presentation"
              onClick={(event) => {
                if (event.target === event.currentTarget) close();
              }}
            >
              <section
                className="image-preview-dialog"
                role="dialog"
                aria-modal="true"
                aria-label={`${alt} full-size preview`}
              >
                <button
                  ref={closeRef}
                  className="image-preview-close"
                  type="button"
                  aria-label="Close image preview"
                  onClick={close}
                >
                  <X aria-hidden="true" weight="bold" />
                </button>
                <img className="image-preview-full" src={src} alt={alt} />
              </section>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
