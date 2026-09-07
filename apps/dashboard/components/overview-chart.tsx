"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

export function OverviewChart({
  values
}: {
  values: Array<{ category: string; count: number }>;
}) {
  return (
    <div className="h-64" aria-label="Aggregate category counts">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={values}>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis dataKey="category" stroke="#64748b" fontSize={11} />
          <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
          <Tooltip
            cursor={{ fill: "#0f172a" }}
            contentStyle={{
              background: "#020617",
              border: "1px solid #334155",
              borderRadius: 8
            }}
          />
          <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
