import Link from "next/link";
import type { ReactNode } from "react";

import { signOut } from "@/actions/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { DashboardContext } from "@/lib/auth";
import { navigationForRole } from "@/lib/navigation";

export function DashboardShell({
  context,
  children
}: {
  context: DashboardContext;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[250px_1fr]">
      <aside className="border-b border-slate-800 bg-slate-950/90 p-4 lg:min-h-screen lg:border-b-0 lg:border-r">
        <div className="mb-6 space-y-2 px-2">
          <Link href="/" className="text-lg font-semibold text-white">
            CodeShield
          </Link>
          <p className="truncate text-xs text-slate-500">
            {context.organizationName}
          </p>
          <Badge>{context.role.replace("_", " ")}</Badge>
        </div>
        <nav aria-label="Management" className="grid gap-1">
          {navigationForRole(context.role).map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="rounded-md px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-slate-900 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <form action={signOut} className="mt-6">
          <Button type="submit" variant="ghost" className="w-full">
            Sign out
          </Button>
        </form>
      </aside>
      <main className="min-w-0 p-5 sm:p-8">{children}</main>
    </div>
  );
}
