import { MetadataTable } from "@/components/metadata-table";
import { PageHeading } from "@/components/page-heading";
import { loadMetadataView, type MetadataViewName } from "@/lib/metadata";

export async function MetadataPage({ view }: { view: MetadataViewName }) {
  const { config, rows } = await loadMetadataView(view);
  return (
    <>
      <PageHeading title={config.title} description={config.description} />
      <MetadataTable rows={rows} columns={config.columns} />
    </>
  );
}
