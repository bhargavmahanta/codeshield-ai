import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Badge({
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-200",
        className
      )}
      {...props}
    />
  );
}
