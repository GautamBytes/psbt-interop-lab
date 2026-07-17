import { Cube } from "@phosphor-icons/react/Cube";

interface BrandProps {
  compact?: boolean;
}

export function Brand({ compact = false }: BrandProps) {
  return (
    <span className={compact ? "brand brand--compact" : "brand"}>
      <span className="brand__mark" aria-hidden="true">
        <Cube weight="duotone" />
      </span>
      <span>PSBT Interop Lab</span>
    </span>
  );
}
