import { issueDeviceToken, revokeDevice } from "@/actions/management";
import { StatefulAction } from "@/components/action-feedback";
import { MetadataTable } from "@/components/metadata-table";
import { PageHeading } from "@/components/page-heading";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { requireDashboardContext } from "@/lib/auth";
import { loadMetadataView } from "@/lib/metadata";

export default async function DevicesPage() {
  const { config, rows } = await loadMetadataView("devices");
  const context = await requireDashboardContext();
  return (
    <div className="space-y-8">
      <div>
        <PageHeading title={config.title} description={config.description} />
        <MetadataTable rows={rows} columns={config.columns} />
      </div>
      {context.role === "administrator" ? (
        <Card>
          <CardHeader>
            <CardTitle>Enroll device</CardTitle>
          </CardHeader>
          <CardContent>
            <StatefulAction action={issueDeviceToken} label="Issue token">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="device_id">Device ID</Label>
                  <Input id="device_id" name="device_id" required maxLength={128} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="display_name">Display name</Label>
                  <Input
                    id="display_name"
                    name="display_name"
                    required
                    maxLength={120}
                  />
                </div>
              </div>
            </StatefulAction>
          </CardContent>
        </Card>
      ) : null}
      {context.role === "administrator" ? (
        <Card>
          <CardHeader>
            <CardTitle>Revoke device</CardTitle>
          </CardHeader>
          <CardContent>
            <form action={revokeDevice} className="flex max-w-xl gap-3">
              <Input
                name="device_uuid"
                aria-label="Device UUID"
                placeholder="Device UUID"
                required
              />
              <Button variant="destructive" type="submit">
                Revoke
              </Button>
            </form>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
