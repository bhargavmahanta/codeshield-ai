import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

import { publicSupabaseConfiguration } from "@/lib/environment";

export async function refreshSession(request: NextRequest) {
  const { url, publishableKey } = publicSupabaseConfiguration();
  let response = NextResponse.next({ request });
  const supabase = createServerClient(url, publishableKey, {
    db: { schema: "api" },
    cookies: {
      getAll: () => request.cookies.getAll(),
      setAll(values) {
        for (const { name, value } of values) {
          request.cookies.set(name, value);
        }
        response = NextResponse.next({ request });
        for (const { name, value, options } of values) {
          response.cookies.set(name, value, {
            ...options,
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production"
          });
        }
      }
    }
  });
  const {
    data: { user }
  } = await supabase.auth.getUser();
  const publicPath =
    request.nextUrl.pathname === "/sign-in" ||
    request.nextUrl.pathname.startsWith("/auth/");
  if (!user && !publicPath) {
    return NextResponse.redirect(new URL("/sign-in", request.url));
  }
  if (user && request.nextUrl.pathname === "/sign-in") {
    return NextResponse.redirect(new URL("/", request.url));
  }
  response.headers.set("Cache-Control", "private, no-store");
  return response;
}
