begin;

create extension if not exists pgcrypto with schema extensions;

create schema if not exists api;
create schema if not exists private;

revoke all on schema public from anon, authenticated;
revoke all on schema api from public, anon, authenticated;
revoke all on schema private from public, anon, authenticated;
grant usage on schema api to authenticated, service_role;
grant usage on schema private to authenticated, service_role;

alter default privileges in schema api revoke all on tables from public, anon, authenticated;
alter default privileges in schema api revoke all on sequences from public, anon, authenticated;
alter default privileges in schema api revoke all on functions from public, anon, authenticated;
alter default privileges in schema private revoke all on tables from public, anon, authenticated;
alter default privileges in schema private revoke all on sequences from public, anon, authenticated;
alter default privileges in schema private revoke all on functions from public, anon, authenticated;

create function private.safe_identifier(value text, maximum integer default 128)
returns boolean
language sql
immutable
strict
set search_path = ''
as $$
  select length(value) between 1 and maximum
    and value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$';
$$;

create function private.safe_metadata_json(candidate jsonb)
returns boolean
language plpgsql
immutable
strict
set search_path = ''
as $$
declare
  item jsonb;
  pair record;
  scalar text;
begin
  case jsonb_typeof(candidate)
    when 'object' then
      for pair in
        select entry.key, entry.value
        from jsonb_each(candidate) as entry(key, value)
      loop
        if pair.key ~* '(prompt|response|source_?code|preview|absolute_?path|file_?path|credential|secret|password|pseudonym|vault|private_?key|key_?material|raw_?(value|finding|content)|request_?body|response_?body|headers?)' then
          return false;
        end if;
        if not private.safe_metadata_json(pair.value) then
          return false;
        end if;
      end loop;
      return true;
    when 'array' then
      for item in select entry.value from jsonb_array_elements(candidate) as entry(value)
      loop
        if not private.safe_metadata_json(item) then
          return false;
        end if;
      end loop;
      return true;
    when 'string' then
      scalar := candidate #>> '{}';
      return length(scalar) <= 512
        and scalar !~ E'^[A-Za-z]:[\\\\/]'
        and scalar !~ E'^[/\\\\]{1,2}'
        and scalar !~* '(-----BEGIN [A-Z ]+-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\\.)';
    when 'number' then
      return true;
    when 'boolean' then
      return true;
    when 'null' then
      return true;
    else
      return false;
  end case;
end;
$$;

create function private.counts_are_safe(value jsonb)
returns boolean
language sql
immutable
strict
set search_path = ''
as $$
  select jsonb_typeof(value) = 'object'
    and not exists (
      select 1
      from jsonb_each(value) as entry(key, item)
      where key !~ '^[A-Z][A-Z0-9_]{0,63}$'
        or jsonb_typeof(item) <> 'number'
        or (item #>> '{}') !~ '^[0-9]{1,10}$'
        or (item #>> '{}')::numeric > 1000000000
    );
$$;

create function private.policy_document_is_safe(value jsonb)
returns boolean
language plpgsql
immutable
strict
set search_path = ''
as $$
declare
  rule jsonb;
begin
  if jsonb_typeof(value) <> 'object'
    or not private.safe_metadata_json(value)
    or value ?| array['content', 'path', 'prompt', 'response', 'preview', 'raw']
    or exists (
      select 1 from jsonb_object_keys(value) as key
      where key not in ('name', 'description_code', 'version', 'rules')
    )
    or jsonb_typeof(value -> 'rules') <> 'array'
    or jsonb_array_length(value -> 'rules') > 256
  then
    return false;
  end if;

  for rule in select item from jsonb_array_elements(value -> 'rules') as item
  loop
    if jsonb_typeof(rule) <> 'object'
      or exists (
        select 1 from jsonb_object_keys(rule) as key
        where key not in (
          'rule_id', 'category', 'action', 'destination_id', 'sensitivity',
          'mandatory', 'remediation_code', 'enabled'
        )
      )
      or not private.safe_identifier(rule ->> 'rule_id')
      or coalesce(rule ->> 'category', '') !~ '^[A-Z][A-Z0-9_]{0,63}$'
      or coalesce(rule ->> 'action', '') not in (
        'allow', 'warn', 'mask', 'pseudonymize', 'block'
      )
      or coalesce(rule ->> 'sensitivity', '') not in (
        'public', 'internal', 'confidential', 'restricted'
      )
      or jsonb_typeof(rule -> 'mandatory') <> 'boolean'
      or not private.safe_identifier(rule ->> 'remediation_code')
    then
      return false;
    end if;
  end loop;
  return true;
end;
$$;

create function private.profile_document_is_safe(value jsonb)
returns boolean
language sql
immutable
strict
set search_path = ''
as $$
  select jsonb_typeof(value) = 'object'
    and private.safe_metadata_json(value)
    and not exists (
      select 1 from jsonb_object_keys(value) as key
      where key not in (
        'profile_id', 'version', 'data_types', 'retention_days', 'training',
        'human_review', 'regions', 'controls', 'source_ids'
      )
    )
    and private.safe_identifier(value ->> 'profile_id')
    and jsonb_typeof(value -> 'version') = 'number'
    and jsonb_typeof(value -> 'data_types') = 'array'
    and jsonb_typeof(value -> 'controls') = 'array';
$$;

create table api.organizations (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  display_name text not null check (length(display_name) between 1 and 120),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table api.memberships (
  organization_id uuid not null references api.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('administrator', 'security_analyst', 'developer')),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);
create index memberships_user_active_idx
  on api.memberships (user_id, organization_id) where active;

create function private.current_membership_role(target_organization uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select membership.role
  from api.memberships as membership
  where membership.organization_id = target_organization
    and membership.user_id = (select auth.uid())
    and membership.active
  limit 1;
$$;

create function private.is_member(target_organization uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from api.memberships as membership
    where membership.organization_id = target_organization
      and membership.user_id = (select auth.uid())
      and membership.active
  );
$$;

create function private.has_role(target_organization uuid, allowed_roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(private.current_membership_role(target_organization) = any(allowed_roles), false);
$$;

revoke all on function private.current_membership_role(uuid) from public, anon;
revoke all on function private.is_member(uuid) from public, anon;
revoke all on function private.has_role(uuid, text[]) from public, anon;
grant execute on function private.current_membership_role(uuid) to authenticated, service_role;
grant execute on function private.is_member(uuid) to authenticated, service_role;
grant execute on function private.has_role(uuid, text[]) to authenticated, service_role;

create table api.provider_profiles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  profile_id text not null check (private.safe_identifier(profile_id)),
  display_name text not null check (length(display_name) between 1 and 120),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, profile_id),
  unique (id, organization_id)
);
create index provider_profiles_org_idx on api.provider_profiles (organization_id, profile_id);

create table api.provider_profile_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  provider_profile_id uuid not null,
  version integer not null check (version > 0),
  status text not null check (status in ('draft', 'released', 'retired')),
  profile_document jsonb not null check (private.profile_document_is_safe(profile_document)),
  evidence_digest text not null check (evidence_digest ~ '^[0-9a-f]{64}$'),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  released_at timestamptz,
  foreign key (provider_profile_id, organization_id)
    references api.provider_profiles(id, organization_id) on delete cascade,
  unique (provider_profile_id, version),
  unique (id, organization_id)
);
create index provider_profile_versions_org_status_idx
  on api.provider_profile_versions (organization_id, status, provider_profile_id);

create table api.provider_sources (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  provider_profile_version_id uuid not null,
  source_id text not null check (private.safe_identifier(source_id)),
  source_kind text not null check (source_kind in ('provider_documentation', 'contract', 'attestation')),
  evidence_digest text not null check (evidence_digest ~ '^[0-9a-f]{64}$'),
  reviewed_at timestamptz not null,
  foreign key (provider_profile_version_id, organization_id)
    references api.provider_profile_versions(id, organization_id) on delete cascade,
  unique (provider_profile_version_id, source_id)
);
create index provider_sources_org_version_idx
  on api.provider_sources (organization_id, provider_profile_version_id);

create table api.destinations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  destination_id text not null check (private.safe_identifier(destination_id)),
  display_name text not null check (length(display_name) between 1 and 120),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, destination_id),
  unique (id, organization_id)
);
create index destinations_org_idx on api.destinations (organization_id, destination_id);

create table api.destination_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  destination_id uuid not null,
  version integer not null check (version > 0),
  sensitivity_ceiling text not null check (
    sensitivity_ceiling in ('public', 'internal', 'confidential', 'restricted')
  ),
  status text not null check (status in ('draft', 'released', 'retired')),
  settings jsonb not null default '{}'::jsonb check (private.safe_metadata_json(settings)),
  created_at timestamptz not null default now(),
  foreign key (destination_id, organization_id)
    references api.destinations(id, organization_id) on delete cascade,
  unique (destination_id, version),
  unique (id, organization_id)
);
create index destination_versions_org_status_idx
  on api.destination_versions (organization_id, status, destination_id);

create table api.policies (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  policy_id text not null check (private.safe_identifier(policy_id)),
  display_name text not null check (length(display_name) between 1 and 120),
  mandatory boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, policy_id),
  unique (id, organization_id)
);
create index policies_org_idx on api.policies (organization_id, policy_id);

create table api.policy_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  policy_id uuid not null,
  version integer not null check (version > 0),
  status text not null check (status in ('draft', 'approved', 'released', 'retired')),
  policy_document jsonb not null check (private.policy_document_is_safe(policy_document)),
  revision integer not null default 1 check (revision > 0),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (policy_id, organization_id)
    references api.policies(id, organization_id) on delete cascade,
  unique (policy_id, version),
  unique (id, organization_id)
);
create index policy_versions_org_status_idx
  on api.policy_versions (organization_id, status, policy_id);

create table api.policy_bundle_releases (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  release_sequence bigint not null check (release_sequence > 0),
  policy_version_id uuid not null,
  minimum_engine_version text not null check (
    minimum_engine_version ~ '^[0-9]+[.][0-9]+[.][0-9]+$'
  ),
  key_id text not null check (private.safe_identifier(key_id)),
  issued_at timestamptz not null,
  expires_at timestamptz not null check (expires_at > issued_at),
  bundle jsonb not null check (private.safe_metadata_json(bundle)),
  signature text not null check (
    length(signature) between 64 and 256
    and signature ~ '^[A-Za-z0-9_-]+$'
  ),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  foreign key (policy_version_id, organization_id)
    references api.policy_versions(id, organization_id),
  unique (organization_id, release_sequence),
  unique (id, organization_id)
);
create index policy_bundle_releases_latest_idx
  on api.policy_bundle_releases (organization_id, release_sequence desc);

create table api.attestations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  attestation_id text not null check (private.safe_identifier(attestation_id)),
  provider_profile_version_id uuid not null,
  status text not null check (status in ('valid', 'missing', 'stale', 'invalid')),
  evidence_digest text check (evidence_digest is null or evidence_digest ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz,
  expires_at timestamptz,
  updated_at timestamptz not null default now(),
  foreign key (provider_profile_version_id, organization_id)
    references api.provider_profile_versions(id, organization_id),
  unique (organization_id, attestation_id)
);
create index attestations_org_status_idx on api.attestations (organization_id, status);

create table api.devices (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  device_id text not null check (private.safe_identifier(device_id)),
  display_name text not null check (length(display_name) between 1 and 120),
  owner_user_id uuid not null references auth.users(id),
  status text not null default 'active' check (status in ('active', 'revoked')),
  last_policy_sequence bigint not null default 0 check (last_policy_sequence >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (organization_id, device_id),
  unique (id, organization_id)
);
create index devices_org_owner_idx on api.devices (organization_id, owner_user_id);
create index devices_active_idx on api.devices (organization_id, id) where status = 'active';

create table private.device_token_hashes (
  device_id uuid primary key references api.devices(id) on delete cascade,
  peppered_hash bytea not null check (octet_length(peppered_hash) = 32),
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);
revoke all on private.device_token_hashes from public, anon, authenticated;

create function api.store_device_token_hash(
  target_device_id uuid,
  digest_hex text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.role()) <> 'service_role' then
    raise insufficient_privilege using message = 'service role required';
  end if;
  if digest_hex !~ '^[0-9a-f]{64}$' then
    raise check_violation using message = 'invalid device token digest';
  end if;
  insert into private.device_token_hashes (device_id, peppered_hash)
  values (target_device_id, decode(digest_hex, 'hex'))
  on conflict (device_id) do update
    set peppered_hash = excluded.peppered_hash,
        created_at = now(),
        revoked_at = null;
end;
$$;

create function api.read_device_token_hash(target_device_id uuid)
returns table (
  organization_id uuid,
  device_status text,
  digest_hex text
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.role()) <> 'service_role' then
    raise insufficient_privilege using message = 'service role required';
  end if;
  return query
    select device.organization_id,
           device.status,
           encode(token.peppered_hash, 'hex')
    from api.devices as device
    join private.device_token_hashes as token on token.device_id = device.id
    where device.id = target_device_id
      and token.revoked_at is null;
end;
$$;

create function api.revoke_device_token(target_device_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.role()) <> 'service_role' then
    raise insufficient_privilege using message = 'service role required';
  end if;
  update private.device_token_hashes
    set revoked_at = now()
    where device_id = target_device_id;
  update api.devices
    set status = 'revoked',
        revoked_at = now(),
        updated_at = now()
    where id = target_device_id;
end;
$$;

revoke all on function api.store_device_token_hash(uuid, text) from public, anon, authenticated;
revoke all on function api.read_device_token_hash(uuid) from public, anon, authenticated;
revoke all on function api.revoke_device_token(uuid) from public, anon, authenticated;
grant execute on function api.store_device_token_hash(uuid, text) to service_role;
grant execute on function api.read_device_token_hash(uuid) to service_role;
grant execute on function api.revoke_device_token(uuid) to service_role;

create table api.detector_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  detector_id text not null check (private.safe_identifier(detector_id)),
  version text not null check (private.safe_identifier(version)),
  status text not null check (status in ('supported', 'deprecated', 'blocked')),
  recorded_at timestamptz not null default now(),
  unique (organization_id, detector_id, version)
);
create index detector_versions_org_idx on api.detector_versions (organization_id, detector_id);

create table api.model_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  model_id text not null check (private.safe_identifier(model_id)),
  version text not null check (private.safe_identifier(version)),
  status text not null check (status in ('supported', 'deprecated', 'blocked')),
  recorded_at timestamptz not null default now(),
  unique (organization_id, model_id, version)
);
create index model_versions_org_idx on api.model_versions (organization_id, model_id);

create table api.safe_feedback (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  submitted_by uuid not null references auth.users(id),
  category text not null check (category ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  action text not null check (action in ('allow', 'warn', 'block', 'protect')),
  sensitivity text not null check (
    sensitivity in ('public', 'internal', 'confidential', 'restricted')
  ),
  status_bucket text not null check (
    status_bucket in ('expected', 'false_positive', 'false_negative', 'needs_review')
  ),
  detector_version text not null check (private.safe_identifier(detector_version)),
  state text not null default 'open' check (state in ('open', 'reviewed', 'closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index safe_feedback_org_state_idx on api.safe_feedback (organization_id, state, created_at desc);

create table api.exceptions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  exception_id text not null check (private.safe_identifier(exception_id)),
  category text not null check (category ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  destination_id text not null check (private.safe_identifier(destination_id)),
  action text not null check (action in ('allow', 'warn')),
  reason_code text not null check (private.safe_identifier(reason_code)),
  status text not null check (status in ('draft', 'approved', 'expired', 'revoked')),
  expires_at timestamptz not null,
  created_by uuid not null references auth.users(id),
  approved_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, exception_id)
);
create index exceptions_org_status_idx on api.exceptions (organization_id, status, expires_at);

create table api.audit_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  device_id uuid not null,
  event_hmac text not null check (event_hmac ~ '^[0-9a-f]{64}$'),
  endpoint_class text not null check (private.safe_identifier(endpoint_class)),
  category_counts jsonb not null check (private.counts_are_safe(category_counts)),
  action_counts jsonb not null check (private.counts_are_safe(action_counts)),
  highest_sensitivity text not null check (
    highest_sensitivity in ('public', 'internal', 'confidential', 'restricted')
  ),
  status_bucket text not null check (
    status_bucket in ('allowed', 'warned', 'blocked', 'protected', 'failed')
  ),
  latency_bucket text not null check (
    latency_bucket in (
      'unknown', 'lt_50ms', 'lt_250ms', 'lt_750ms', 'lt_2s', 'gte_2s'
    )
  ),
  detector_version text not null check (private.safe_identifier(detector_version)),
  model_version text check (model_version is null or private.safe_identifier(model_version)),
  occurred_at timestamptz not null,
  received_at timestamptz not null default now(),
  foreign key (device_id, organization_id)
    references api.devices(id, organization_id),
  unique (organization_id, event_hmac)
);
create index audit_events_org_time_idx on api.audit_events (organization_id, occurred_at desc);
create index audit_events_org_status_idx on api.audit_events (organization_id, status_bucket, occurred_at desc);

create table api.compliance_summaries (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references api.organizations(id) on delete cascade,
  period_start date not null,
  period_end date not null check (period_end >= period_start),
  category_counts jsonb not null check (private.counts_are_safe(category_counts)),
  action_counts jsonb not null check (private.counts_are_safe(action_counts)),
  highest_sensitivity text not null check (
    highest_sensitivity in ('public', 'internal', 'confidential', 'restricted')
  ),
  generated_at timestamptz not null default now(),
  unique (organization_id, period_start, period_end)
);
create index compliance_summaries_org_period_idx
  on api.compliance_summaries (organization_id, period_end desc);

create function private.touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create function private.reject_release_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception using errcode = '55000', message = 'policy bundle releases are immutable';
end;
$$;

create function private.enforce_release_sequence()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  latest bigint;
begin
  perform pg_advisory_xact_lock(hashtextextended(new.organization_id::text, 0));
  select max(release_sequence)
    into latest
    from api.policy_bundle_releases
    where organization_id = new.organization_id;
  if latest is not null and new.release_sequence <= latest then
    raise exception using errcode = '23514', message = 'release sequence must increase';
  end if;
  return new;
end;
$$;

create trigger organizations_touch before update on api.organizations
  for each row execute function private.touch_updated_at();
create trigger memberships_touch before update on api.memberships
  for each row execute function private.touch_updated_at();
create trigger provider_profiles_touch before update on api.provider_profiles
  for each row execute function private.touch_updated_at();
create trigger destinations_touch before update on api.destinations
  for each row execute function private.touch_updated_at();
create trigger policies_touch before update on api.policies
  for each row execute function private.touch_updated_at();
create trigger policy_versions_touch before update on api.policy_versions
  for each row execute function private.touch_updated_at();
create trigger attestations_touch before update on api.attestations
  for each row execute function private.touch_updated_at();
create trigger devices_touch before update on api.devices
  for each row execute function private.touch_updated_at();
create trigger safe_feedback_touch before update on api.safe_feedback
  for each row execute function private.touch_updated_at();
create trigger exceptions_touch before update on api.exceptions
  for each row execute function private.touch_updated_at();
create trigger policy_bundle_sequence before insert on api.policy_bundle_releases
  for each row execute function private.enforce_release_sequence();
create trigger policy_bundle_immutable before update or delete on api.policy_bundle_releases
  for each row execute function private.reject_release_mutation();

alter table api.organizations enable row level security;
alter table api.memberships enable row level security;
alter table api.provider_profiles enable row level security;
alter table api.provider_profile_versions enable row level security;
alter table api.provider_sources enable row level security;
alter table api.destinations enable row level security;
alter table api.destination_versions enable row level security;
alter table api.policies enable row level security;
alter table api.policy_versions enable row level security;
alter table api.policy_bundle_releases enable row level security;
alter table api.attestations enable row level security;
alter table api.devices enable row level security;
alter table api.detector_versions enable row level security;
alter table api.model_versions enable row level security;
alter table api.safe_feedback enable row level security;
alter table api.exceptions enable row level security;
alter table api.audit_events enable row level security;
alter table api.compliance_summaries enable row level security;

alter table api.organizations force row level security;
alter table api.memberships force row level security;
alter table api.provider_profiles force row level security;
alter table api.provider_profile_versions force row level security;
alter table api.provider_sources force row level security;
alter table api.destinations force row level security;
alter table api.destination_versions force row level security;
alter table api.policies force row level security;
alter table api.policy_versions force row level security;
alter table api.policy_bundle_releases force row level security;
alter table api.attestations force row level security;
alter table api.devices force row level security;
alter table api.detector_versions force row level security;
alter table api.model_versions force row level security;
alter table api.safe_feedback force row level security;
alter table api.exceptions force row level security;
alter table api.audit_events force row level security;
alter table api.compliance_summaries force row level security;

create policy organizations_member_select on api.organizations
  for select to authenticated using (private.is_member(id));
create policy organizations_admin_update on api.organizations
  for update to authenticated
  using (private.has_role(id, array['administrator']))
  with check (private.has_role(id, array['administrator']));

create policy memberships_member_select on api.memberships
  for select to authenticated using (private.is_member(organization_id));
create policy memberships_admin_insert on api.memberships
  for insert to authenticated
  with check (private.has_role(organization_id, array['administrator']));
create policy memberships_admin_update on api.memberships
  for update to authenticated
  using (private.has_role(organization_id, array['administrator']))
  with check (private.has_role(organization_id, array['administrator']));
create policy memberships_admin_delete on api.memberships
  for delete to authenticated
  using (private.has_role(organization_id, array['administrator']));

create policy provider_profiles_member_select on api.provider_profiles
  for select to authenticated using (private.is_member(organization_id));
create policy provider_profiles_reviewer_write on api.provider_profiles
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy provider_versions_select on api.provider_profile_versions
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
    or (private.is_member(organization_id) and status = 'released')
  );
create policy provider_versions_reviewer_write on api.provider_profile_versions
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy provider_sources_select on api.provider_sources
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
    or (
      private.is_member(organization_id)
      and exists (
        select 1 from api.provider_profile_versions as version
        where version.id = provider_profile_version_id
          and version.organization_id = provider_sources.organization_id
          and version.status = 'released'
      )
    )
  );
create policy provider_sources_reviewer_write on api.provider_sources
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy destinations_member_select on api.destinations
  for select to authenticated using (private.is_member(organization_id));
create policy destinations_admin_write on api.destinations
  for all to authenticated
  using (private.has_role(organization_id, array['administrator']))
  with check (private.has_role(organization_id, array['administrator']));

create policy destination_versions_select on api.destination_versions
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
    or (private.is_member(organization_id) and status = 'released')
  );
create policy destination_versions_admin_write on api.destination_versions
  for all to authenticated
  using (private.has_role(organization_id, array['administrator']))
  with check (private.has_role(organization_id, array['administrator']));

create policy policies_member_select on api.policies
  for select to authenticated using (private.is_member(organization_id));
create policy policies_reviewer_write on api.policies
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy policy_versions_select on api.policy_versions
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
    or (private.is_member(organization_id) and status = 'released')
  );
create policy policy_versions_reviewer_write on api.policy_versions
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy releases_member_select on api.policy_bundle_releases
  for select to authenticated using (private.is_member(organization_id));
create policy releases_admin_insert on api.policy_bundle_releases
  for insert to authenticated
  with check (private.has_role(organization_id, array['administrator']));

create policy attestations_member_select on api.attestations
  for select to authenticated using (private.is_member(organization_id));
create policy attestations_reviewer_write on api.attestations
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy devices_member_select on api.devices
  for select to authenticated using (
    private.has_role(organization_id, array['administrator'])
    or (private.is_member(organization_id) and owner_user_id = (select auth.uid()))
  );
create policy devices_admin_or_owner_insert on api.devices
  for insert to authenticated with check (
    private.has_role(organization_id, array['administrator'])
    or (private.is_member(organization_id) and owner_user_id = (select auth.uid()))
  );
create policy devices_admin_or_owner_update on api.devices
  for update to authenticated
  using (
    private.has_role(organization_id, array['administrator'])
    or (private.is_member(organization_id) and owner_user_id = (select auth.uid()))
  )
  with check (
    private.has_role(organization_id, array['administrator'])
    or (
      private.is_member(organization_id)
      and owner_user_id = (select auth.uid())
      and status = 'active'
    )
  );
create policy devices_admin_delete on api.devices
  for delete to authenticated
  using (private.has_role(organization_id, array['administrator']));

create policy detector_versions_member_select on api.detector_versions
  for select to authenticated using (private.is_member(organization_id));
create policy detector_versions_reviewer_write on api.detector_versions
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));
create policy model_versions_member_select on api.model_versions
  for select to authenticated using (private.is_member(organization_id));
create policy model_versions_reviewer_write on api.model_versions
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy feedback_member_insert on api.safe_feedback
  for insert to authenticated with check (
    private.is_member(organization_id) and submitted_by = (select auth.uid())
  );
create policy feedback_owner_or_reviewer_select on api.safe_feedback
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
    or (private.is_member(organization_id) and submitted_by = (select auth.uid()))
  );
create policy feedback_reviewer_update on api.safe_feedback
  for update to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy exceptions_reviewer_select on api.exceptions
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
  );
create policy exceptions_reviewer_write on api.exceptions
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

create policy audit_events_member_insert on api.audit_events
  for insert to authenticated with check (
    private.is_member(organization_id)
    and exists (
      select 1 from api.devices as device
      where device.id = audit_events.device_id
        and device.organization_id = audit_events.organization_id
        and device.owner_user_id = (select auth.uid())
        and device.status = 'active'
    )
  );
create policy audit_events_reviewer_select on api.audit_events
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
  );

create policy compliance_reviewer_select on api.compliance_summaries
  for select to authenticated using (
    private.has_role(organization_id, array['administrator', 'security_analyst'])
  );
create policy compliance_reviewer_write on api.compliance_summaries
  for all to authenticated
  using (private.has_role(organization_id, array['administrator', 'security_analyst']))
  with check (private.has_role(organization_id, array['administrator', 'security_analyst']));

grant select, update on api.organizations to authenticated;
grant select, insert, update, delete on api.memberships to authenticated;
grant select, insert, update, delete on api.provider_profiles to authenticated;
grant select, insert, update, delete on api.provider_profile_versions to authenticated;
grant select, insert, update, delete on api.provider_sources to authenticated;
grant select, insert, update, delete on api.destinations to authenticated;
grant select, insert, update, delete on api.destination_versions to authenticated;
grant select, insert, update, delete on api.policies to authenticated;
grant select, insert, update, delete on api.policy_versions to authenticated;
grant select, insert on api.policy_bundle_releases to authenticated;
grant select, insert, update, delete on api.attestations to authenticated;
grant select, insert, update, delete on api.devices to authenticated;
grant select, insert, update, delete on api.detector_versions to authenticated;
grant select, insert, update, delete on api.model_versions to authenticated;
grant select, insert, update on api.safe_feedback to authenticated;
grant select, insert, update, delete on api.exceptions to authenticated;
grant select, insert on api.audit_events to authenticated;
grant select, insert, update, delete on api.compliance_summaries to authenticated;

grant all on all tables in schema api to service_role;
grant all on all tables in schema private to service_role;
grant execute on all functions in schema private to service_role;

revoke all on all tables in schema api from anon;
revoke all on all sequences in schema api from anon;
revoke all on all functions in schema api from anon;
revoke all on all tables in schema private from anon, authenticated;
revoke all on all sequences in schema private from anon, authenticated;
revoke all on all functions in schema private from anon, authenticated;
grant execute on function private.current_membership_role(uuid) to authenticated;
grant execute on function private.is_member(uuid) to authenticated;
grant execute on function private.has_role(uuid, text[]) to authenticated;

commit;
