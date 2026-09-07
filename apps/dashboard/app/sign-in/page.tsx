import type { Metadata } from "next";

import { signIn } from "@/actions/auth";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const metadata: Metadata = { title: "Sign in" };

export default async function SignInPage({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  return (
    <main className="grid min-h-screen place-items-center px-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            CodeShield
          </p>
          <CardTitle className="text-2xl">Private management</CardTitle>
          <CardDescription>
            Invite-only access to organizational security metadata.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form action={signIn} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                required
                maxLength={254}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                maxLength={256}
              />
            </div>
            {error ? (
              <p role="alert" className="text-sm text-rose-400">
                Sign-in could not be completed.
              </p>
            ) : null}
            <Button type="submit" className="w-full">
              Sign in
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
