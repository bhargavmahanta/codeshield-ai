import type { Metadata } from "next";
import type { ReactNode } from "react";

import "@/app/globals.css";

export const metadata: Metadata = {
  title: {
    default: "CodeShield Management",
    template: "%s · CodeShield"
  },
  description: "Private metadata-only CodeShield organizational management."
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
