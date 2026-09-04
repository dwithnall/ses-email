import type { ReactNode } from "react";

export default function PageHeader({
  title,
  subtitle,
}: {
  title: string;
  subtitle?: ReactNode;
}) {
  return (
    <div className="border-b border-brand-100 bg-brand-50">
      <div className="mx-auto max-w-6xl px-4 py-12">
        <h1 className="text-3xl font-bold text-brand-900 sm:text-4xl">{title}</h1>
        {subtitle && <p className="mt-3 max-w-2xl text-brand-700">{subtitle}</p>}
      </div>
    </div>
  );
}
