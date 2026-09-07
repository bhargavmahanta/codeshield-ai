import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

import { publicSupabaseConfiguration } from "@/lib/environment";

export async function createServerSupabaseClient() {
  const cookieStore = await cookies();
  const { url, publishableKey } = publicSupabaseConfiguration();

  return createServerClient(url, publishableKey, {
    db: { schema: "api" },
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(values) {
        try {
          for (const { name, value, options } of values) {
            cookieStore.set(name, value, {
              ...options,
              httpOnly: true,
              sameSite: "lax",
              secure: process.env.NODE_ENV === "production"
            });
          }
        } catch {
          // A Server Component cannot set cookies. proxy.ts refreshes them.
        }
      }
    }
  });
}
