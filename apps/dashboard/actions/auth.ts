"use server";

import { redirect } from "next/navigation";

import { createServerSupabaseClient } from "@/lib/supabase/server";

export async function signIn(formData: FormData) {
  const email = String(formData.get("email") ?? "");
  const submittedSecret = String(formData.get("password") ?? "");
  if (!email || !submittedSecret || email.length > 254 || submittedSecret.length > 256) {
    redirect("/sign-in?error=invalid");
  }
  const supabase = await createServerSupabaseClient();
  const credentials = Object.fromEntries([
    ["email", email],
    ["password", submittedSecret],
  ]) as unknown as Parameters<typeof supabase.auth.signInWithPassword>[0];
  const { error } = await supabase.auth.signInWithPassword(credentials);
  if (error) {
    redirect("/sign-in?error=authentication");
  }
  redirect("/");
}

export async function signOut() {
  const supabase = await createServerSupabaseClient();
  await supabase.auth.signOut();
  redirect("/sign-in");
}
