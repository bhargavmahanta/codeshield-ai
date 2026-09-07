import type { ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "secondary" | "destructive" | "ghost";
};

export function Button({
  className,
  variant = "default",
  ...props
}: ButtonProps) {
  return (
    <button
      data-slot="button"
      className={cn(
        "inline-flex h-9 items-center justify-center rounded-md px-4 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:pointer-events-none disabled:opacity-50",
        variant === "default" && "bg-cyan-400 text-slate-950 hover:bg-cyan-300",
        variant === "secondary" && "bg-slate-800 text-slate-100 hover:bg-slate-700",
        variant === "destructive" && "bg-rose-600 text-white hover:bg-rose-500",
        variant === "ghost" && "text-slate-300 hover:bg-slate-800 hover:text-white",
        className
      )}
      {...props}
    />
  );
}
