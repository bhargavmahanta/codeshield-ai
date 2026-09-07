import { expect, test } from "@playwright/test";
import { randomBytes, randomUUID } from "node:crypto";

const supabaseUrl =
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? "http://127.0.0.1:54321";
const serviceCredential = process.env.SUPABASE_SERVICE_ROLE_KEY;
const organizationId = "11111111-1111-4111-8111-111111111111";

test("unauthenticated requests receive the invite-only sign-in page", async ({
  page
}) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/sign-in$/u);
  await expect(
    page.getByRole("heading", { name: "Private management" })
  ).toBeVisible();
  await expect(page.getByText("Invite-only access")).toBeVisible();
  await expect(page.locator("body")).not.toContainText(
    /prompt|source path|raw finding|pseudonym mapping/iu
  );
});

test("local Auth and RLS expose only the developer tenant surface", async ({
  page,
  request
}) => {
  test.skip(!serviceCredential, "local Supabase service credential is required");
  const email = `dashboard-${randomUUID()}@example.invalid`;
  const password = randomBytes(32).toString("base64url");
  const headers = {
    apikey: serviceCredential!,
    authorization: `Bearer ${serviceCredential!}`,
    "content-type": "application/json"
  };
  const created = await request.post(`${supabaseUrl}/auth/v1/admin/users`, {
    headers,
    data: { email, password, email_confirm: true }
  });
  expect(created.ok()).toBeTruthy();
  const user = (await created.json()) as { id: string };
  const membership = await request.post(
    `${supabaseUrl}/rest/v1/memberships`,
    {
      headers: {
        ...headers,
        "accept-profile": "api",
        "content-profile": "api"
      },
      data: {
        organization_id: organizationId,
        user_id: user.id,
        role: "developer",
        active: true
      }
    }
  );
  expect(membership.ok()).toBeTruthy();
  try {
    await page.goto("/sign-in");
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL("/");
    await expect(page.getByText("Synthetic Alpha")).toBeVisible();
    await expect(page.getByText("developer", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Members" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Settings" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Audit metadata" })).toHaveCount(
      0
    );
    await page.getByRole("link", { name: "Provider history" }).click();
    await expect(
      page.getByRole("heading", { name: "Provider history" })
    ).toBeVisible();
    await expect(page.getByText("Synthetic Beta")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(
      /source code|absolute path|raw finding|pseudonym mapping/iu
    );
  } finally {
    await request.delete(`${supabaseUrl}/auth/v1/admin/users/${user.id}`, {
      headers
    });
  }
});
