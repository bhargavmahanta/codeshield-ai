import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { displayValue, type MetadataRow } from "@/lib/metadata";

export function MetadataTable({
  rows,
  columns
}: {
  rows: MetadataRow[];
  columns: readonly string[];
}) {
  if (!rows.length) {
    return (
      <div className="rounded-xl border border-dashed border-slate-700 p-10 text-center">
        <p className="text-sm font-medium text-slate-300">No metadata yet</p>
        <p className="mt-1 text-xs text-slate-500">
          Nothing has been recorded for this organization.
        </p>
      </div>
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {columns.map((column) => (
            <TableHead key={column}>{column.replaceAll("_", " ")}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row, rowIndex) => (
          <TableRow key={String(row.id ?? rowIndex)}>
            {columns.map((column) => (
              <TableCell key={column}>
                {column === "status" || column.endsWith("_sensitivity") ? (
                  <Badge>{displayValue(row[column])}</Badge>
                ) : (
                  <span className="max-w-xs truncate font-mono text-xs">
                    {displayValue(row[column])}
                  </span>
                )}
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
