"use client";

import { Button } from "@/components/ui/button";

export default function ErrorBoundary({
  reset
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="grid min-h-screen place-items-center p-6">
      <div className="max-w-md space-y-4 text-center">
        <h1 className="text-xl font-semibold">Metadata could not be loaded</h1>
        <p className="text-sm text-slate-400">
          CodeShield rejected an unavailable or invalid management response.
        </p>
        <Button onClick={reset}>Try again</Button>
      </div>
    </main>
  );
}
