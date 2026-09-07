import { describe, expect, it } from "vitest";

import { navigationForRole } from "@/lib/navigation";

describe("role-aware navigation", () => {
  it("limits developers to released metadata workflows", () => {
    const hrefs = navigationForRole("developer").map((item) => item.href);
    expect(hrefs).not.toContain("/members");
    expect(hrefs).not.toContain("/settings");
    expect(hrefs).not.toContain("/audit");
    expect(hrefs).toContain("/providers");
    expect(hrefs).toContain("/devices");
  });

  it("gives administrators tenant administration workflows", () => {
    const hrefs = navigationForRole("administrator").map((item) => item.href);
    expect(hrefs).toContain("/members");
    expect(hrefs).toContain("/settings");
  });
});
