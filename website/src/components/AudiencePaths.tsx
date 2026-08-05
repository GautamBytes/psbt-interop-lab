import { Binoculars } from "@phosphor-icons/react/Binoculars";
import { BracketsCurly } from "@phosphor-icons/react/BracketsCurly";
import { Wallet } from "@phosphor-icons/react/Wallet";
import { SiteLink } from "./SiteLink";

const paths = [
  {
    icon: Wallet,
    label: "I maintain a wallet",
    detail: "Generate an adapter, run wallet-focused CI, and upload replayable evidence.",
    action: "Connect a wallet",
    href: "/adapter-kit",
  },
  {
    icon: BracketsCurly,
    label: "I maintain a library",
    detail: "Exercise native parsing, deterministic mutations, and cross-library handoffs.",
    action: "Test an implementation",
    href: "/docs#differential-fuzzing",
  },
  {
    icon: Binoculars,
    label: "I review protocol behavior",
    detail: "Inspect sourced findings, exact checkpoints, and replay-verified reports.",
    action: "Review the evidence",
    href: "/docs#walkthrough-verify-the-complete-matrix",
  },
] as const;

export function AudiencePaths() {
  return (
    <section className="audience-paths page-shell" aria-labelledby="audience-paths-title">
      <header className="audience-paths__heading">
        <span className="eyebrow">Choose your path</span>
        <h2 id="audience-paths-title">Start with the job you need to finish.</h2>
      </header>
      <div className="audience-paths__grid">
        {paths.map(({ icon: Icon, label, detail, action, href }) => (
          <SiteLink className="audience-path" href={href} key={label}>
            <Icon aria-hidden="true" weight="duotone" />
            <span>
              <strong>{label}</strong>
              <small>{detail}</small>
            </span>
            <em>{action} →</em>
          </SiteLink>
        ))}
      </div>
    </section>
  );
}
