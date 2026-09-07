import type { InputHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Input({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400",
        className
      )}
      {...props}
    />
  );
}
