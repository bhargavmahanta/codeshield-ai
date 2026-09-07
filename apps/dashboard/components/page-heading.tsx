export function PageHeading({
  title,
  description
}: {
  title: string;
  description: string;
}) {
  return (
    <header className="mb-6 space-y-2">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
        Metadata only
      </p>
      <h1 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
        {title}
      </h1>
      <p className="max-w-3xl text-sm text-slate-400">{description}</p>
    </header>
  );
}
