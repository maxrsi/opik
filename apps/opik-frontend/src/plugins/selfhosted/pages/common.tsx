import React from "react";

export const formatTime = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString() : "—";

export const PageShell: React.FC<{
  title: string;
  description?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}> = ({ title, description, actions, children }) => (
  <div className="flex flex-col gap-4 pt-6">
    <div className="flex items-center justify-between gap-4">
      <div>
        <h1 className="comet-title-l">{title}</h1>
        {description && (
          <p className="comet-body-s text-muted-slate">{description}</p>
        )}
      </div>
      <div className="flex items-center gap-2">{actions}</div>
    </div>
    {children}
  </div>
);

export const Forbidden: React.FC = () => (
  <div className="comet-body py-24 text-center text-muted-slate">
    You don&apos;t have permission to view this page.
  </div>
);

export const SecretBox: React.FC<{ label: string; value: string }> = ({
  label,
  value,
}) => (
  <div className="flex flex-col gap-2 rounded-md border bg-soft-background p-3">
    <span className="comet-body-xs text-muted-slate">{label}</span>
    <code className="comet-code break-all">{value}</code>
    <span className="comet-body-xs text-muted-slate">
      Copy it now, it will not be shown again.
    </span>
  </div>
);
