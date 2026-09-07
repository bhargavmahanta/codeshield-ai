import { submitFeedback } from "@/actions/management";
import { MetadataPage } from "@/components/metadata-page";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function FeedbackPage() {
  return (
    <div className="space-y-8">
      <MetadataPage view="feedback" />
      <Card>
        <CardHeader>
          <CardTitle>Submit safe feedback</CardTitle>
        </CardHeader>
        <CardContent>
          <form action={submitFeedback} className="grid gap-4 sm:grid-cols-2">
            <Field name="category" label="Category" placeholder="API_KEY" />
            <Field
              name="detector_version"
              label="Detector version"
              placeholder="0.9.0"
            />
            <SelectField
              name="action"
              label="Action"
              values={["allow", "warn", "block", "protect"]}
            />
            <SelectField
              name="sensitivity"
              label="Sensitivity"
              values={[
                "public",
                "internal",
                "confidential",
                "restricted"
              ]}
            />
            <SelectField
              name="status_bucket"
              label="Feedback type"
              values={[
                "expected",
                "false_positive",
                "false_negative",
                "needs_review"
              ]}
            />
            <div className="flex items-end">
              <Button type="submit">Submit metadata</Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({
  name,
  label,
  placeholder
}: {
  name: string;
  label: string;
  placeholder: string;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={name}>{label}</Label>
      <Input
        id={name}
        name={name}
        placeholder={placeholder}
        required
        maxLength={128}
      />
    </div>
  );
}

function SelectField({
  name,
  label,
  values
}: {
  name: string;
  label: string;
  values: string[];
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={name}>{label}</Label>
      <select
        id={name}
        name={name}
        className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm"
      >
        {values.map((value) => (
          <option key={value}>{value}</option>
        ))}
      </select>
    </div>
  );
}
