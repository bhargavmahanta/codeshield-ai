const LOOPBACK_ORIGIN =
  /^http:\/\/(?:127[.]0[.]0[.]1|localhost|\[::1\])(?::[0-9]{1,5})?$/u;

export function publicSupabaseConfiguration() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !publishableKey || !LOOPBACK_ORIGIN.test(url)) {
    throw new Error("CS_DASHBOARD_CONFIGURATION");
  }
  return { url, publishableKey };
}

export function managementApiOrigin() {
  const value = process.env.CODESHIELD_MANAGEMENT_API_URL;
  if (!value || !LOOPBACK_ORIGIN.test(value)) {
    throw new Error("CS_DASHBOARD_MANAGEMENT_CONFIGURATION");
  }
  return value;
}
