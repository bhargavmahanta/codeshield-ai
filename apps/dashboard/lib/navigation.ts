import type { OrganizationRole } from "@/lib/auth";

export type NavigationItem = {
  href: string;
  label: string;
  roles: OrganizationRole[];
};

export const navigationItems: NavigationItem[] = [
  { href: "/", label: "Overview", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/findings", label: "Aggregate findings", roles: ["administrator", "security_analyst"] },
  { href: "/audit", label: "Audit metadata", roles: ["administrator", "security_analyst"] },
  { href: "/providers", label: "Provider history", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/destinations", label: "Destinations", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/policies", label: "Policies", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/devices", label: "Devices", roles: ["administrator", "developer"] },
  { href: "/attestations", label: "Attestations", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/feedback", label: "Feedback", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/exceptions", label: "Exceptions", roles: ["administrator", "security_analyst"] },
  { href: "/versions", label: "Models & detectors", roles: ["administrator", "security_analyst", "developer"] },
  { href: "/members", label: "Members", roles: ["administrator"] },
  { href: "/settings", label: "Settings", roles: ["administrator"] }
];

export function navigationForRole(role: OrganizationRole) {
  return navigationItems.filter((item) => item.roles.includes(role));
}
