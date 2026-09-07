"use client";

import { useActionState, type ReactNode } from "react";

import type { ActionState } from "@/actions/management";
import { Button } from "@/components/ui/button";

export function StatefulAction({
  action,
  label,
  children
}: {
  action: (state: ActionState, formData: FormData) => Promise<ActionState>;
  label: string;
  children: ReactNode;
}) {
  const [state, formAction, pending] = useActionState(action, {
    status: "idle"
  } satisfies ActionState);
  return (
    <form action={formAction} className="space-y-4">
      {children}
      <Button type="submit" disabled={pending}>
        {pending ? "Working\u2026" : label}
      </Button>
      {state.status !== "idle" ? (
        <p
          role="status"
          className={
            state.status === "success"
              ? "text-sm text-emerald-400"
              : "text-sm text-rose-400"
          }
        >
          {state.status === "success"
            ? state.code ?? "Completed."
            : state.code ?? "The operation could not be completed."}
        </p>
      ) : null}
      {state.token ? (
        <div className="rounded-md border border-amber-600/50 bg-amber-950/30 p-3">
          <p className="text-xs font-semibold text-amber-300">
            Copy now. This token is shown once.
          </p>
          <code className="mt-2 block break-all text-xs text-amber-100">
            {state.token}
          </code>
        </div>
      ) : null}
    </form>
  );
}
