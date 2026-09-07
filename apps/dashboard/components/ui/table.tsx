import type { HTMLAttributes, TableHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Table({
  className,
  ...props
}: TableHTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto rounded-lg border border-slate-800">
      <table
        className={cn("w-full caption-bottom text-sm", className)}
        {...props}
      />
    </div>
  );
}

export function TableHeader(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className="bg-slate-900 text-left text-slate-400" {...props} />;
}

export function TableBody(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className="divide-y divide-slate-800" {...props} />;
}

export function TableRow(props: HTMLAttributes<HTMLTableRowElement>) {
  return <tr className="hover:bg-slate-900/70" {...props} />;
}

export function TableHead(props: HTMLAttributes<HTMLTableCellElement>) {
  return <th className="h-10 whitespace-nowrap px-3 font-medium" {...props} />;
}

export function TableCell(props: HTMLAttributes<HTMLTableCellElement>) {
  return <td className="whitespace-nowrap px-3 py-3 text-slate-200" {...props} />;
}
