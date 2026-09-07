begin;

create extension if not exists pgtap with schema extensions;
set search_path = public, extensions;

select plan(39);

select has_schema('api', 'api schema exists');
select has_schema('private', 'private schema exists');
select has_table('api', 'organizations', 'organizations table exists');
select has_table('api', 'policy_bundle_releases', 'release table exists');
select has_table('private', 'device_token_hashes', 'token hashes remain private');

select is(
  (
    select count(*)::integer
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'api'
      and relation.relkind = 'r'
      and relation.relrowsecurity
  ),
  18,
  'every API table has RLS enabled'
);
select is(
  (
    select count(*)::integer
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'api'
      and relation.relkind = 'r'
      and relation.relforcerowsecurity
  ),
  18,
  'every API table forces RLS'
);
select is(
  has_schema_privilege('anon', 'api', 'usage'),
  false,
  'anonymous users cannot use the business API schema'
);
select is(
  has_table_privilege('anon', 'api.organizations', 'select'),
  false,
  'anonymous users have no organization access'
);
select is(
  has_table_privilege('authenticated', 'private.device_token_hashes', 'select'),
  false,
  'authenticated users cannot read token hashes'
);
select is(
  has_schema_privilege('authenticated', 'private', 'usage'),
  true,
  'authenticated users can resolve allowlisted private authorization helpers'
);
select is(
  has_function_privilege(
    'anon',
    'private.current_membership_role(uuid)',
    'execute'
  ),
  false,
  'anonymous users cannot execute authorization helpers'
);
select is(
  has_function_privilege(
    'authenticated',
    'private.current_membership_role(uuid)',
    'execute'
  ),
  true,
  'authenticated users can execute only the membership helper used by RLS'
);

insert into api.policy_bundle_releases (
  id, organization_id, release_sequence, policy_version_id,
  minimum_engine_version, key_id, issued_at, expires_at, bundle,
  signature, created_by
) values (
  '11111111-f001-4111-8111-111111111111',
  '11111111-1111-4111-8111-111111111111',
  1,
  '11111111-c101-4111-8111-111111111111',
  '0.9.0',
  'local-test-key',
  now(),
  now() + interval '1 day',
  '{
    "organization_id":"11111111-1111-4111-8111-111111111111",
    "release_sequence":1,
    "policy_version_id":"11111111-c101-4111-8111-111111111111",
    "minimum_engine_version":"0.9.0",
    "key_id":"local-test-key"
  }',
  repeat('A', 86),
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
);

select throws_ok(
  $test$
    update api.policy_bundle_releases
    set expires_at = expires_at + interval '1 hour'
    where id = '11111111-f001-4111-8111-111111111111'
  $test$,
  '55000',
  'policy bundle releases are immutable',
  'released bundles cannot be updated'
);
select throws_ok(
  $test$
    insert into api.policy_bundle_releases (
      organization_id, release_sequence, policy_version_id,
      minimum_engine_version, key_id, issued_at, expires_at, bundle,
      signature, created_by
    ) values (
      '11111111-1111-4111-8111-111111111111',
      1,
      '11111111-c101-4111-8111-111111111111',
      '0.9.0',
      'local-test-key',
      now(),
      now() + interval '1 day',
      '{"release_sequence":1}',
      repeat('A', 86),
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
    )
  $test$,
  '23514',
  'release sequence must increase',
  'release sequence rollback is rejected'
);

insert into api.provider_profile_versions (
  id, organization_id, provider_profile_id, version, status,
  profile_document, evidence_digest, created_by
) values (
  '11111111-a002-4111-8111-111111111111',
  '11111111-1111-4111-8111-111111111111',
  '11111111-aaaa-4111-8111-111111111111',
  2,
  'draft',
  '{
    "profile_id":"synthetic-provider",
    "version":2,
    "data_types":["prompt"],
    "retention_days":0,
    "training":false,
    "human_review":false,
    "regions":["local"],
    "controls":["no-retention"],
    "source_ids":["synthetic-source"]
  }',
  repeat('1', 64),
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'
);

select is(
  private.safe_metadata_json('{"category":"API_KEY","count":2}'::jsonb),
  true,
  'structured metadata is accepted'
);
select is(
  private.safe_metadata_json('{"prompt":"do not persist this"}'::jsonb),
  false,
  'prompt fields are rejected'
);
select is(
  private.safe_metadata_json('{"location":"C:\\private\\file.py"}'::jsonb),
  false,
  'absolute paths are rejected'
);
select is(
  private.safe_metadata_json('{"credential":"synthetic"}'::jsonb),
  false,
  'credential fields are rejected'
);
select is(
  private.counts_are_safe('{"API_KEY":2,"EMAIL":1}'::jsonb),
  true,
  'bounded aggregate counts are accepted'
);
select is(
  private.counts_are_safe('{"API_KEY":"two"}'::jsonb),
  false,
  'non-numeric aggregate counts are rejected'
);
select is(
  private.policy_document_is_safe(
    (
      select policy_document
      from api.policy_versions
      where id = '11111111-c101-4111-8111-111111111111'
    )
  ),
  true,
  'the committed synthetic policy uses the approved document shape'
);
select is(
  private.policy_document_is_safe(
    '{"name":"bad","rules":[],"content":"not allowed"}'::jsonb
  ),
  false,
  'arbitrary policy content is rejected'
);

set local role authenticated;
select set_config(
  'request.jwt.claim.sub',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',
  true
);

select is(
  (select count(*) from api.organizations),
  1::bigint,
  'an administrator sees only their organization'
);
select is(
  (select count(*) from api.memberships),
  3::bigint,
  'an administrator sees memberships only in their organization'
);
select is(
  (
    select role
    from api.memberships
    where user_id = (select auth.uid())
  ),
  'administrator',
  'administrator authority comes from the membership row'
);
select is(
  (
    select count(*)
    from api.memberships
    where organization_id = '22222222-2222-4222-8222-222222222222'
  ),
  0::bigint,
  'membership helpers deny the second organization'
);
select lives_ok(
  $test$
    update api.destinations
    set display_name = 'Local destination'
    where id = '11111111-d001-4111-8111-111111111111'
  $test$,
  'administrators can administer destinations'
);
select is(
  (
    select count(*)
    from api.devices
    where organization_id = '22222222-2222-4222-8222-222222222222'
  ),
  0::bigint,
  'administrator device access cannot cross tenants'
);

select set_config(
  'request.jwt.claim.sub',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2',
  true
);
select is(
  (
    select role
    from api.memberships
    where user_id = (select auth.uid())
  ),
  'security_analyst',
  'security analyst authority comes from the membership row'
);
select is(
  (
    select count(*)
    from api.provider_profile_versions
    where status = 'draft'
  ),
  1::bigint,
  'security analysts can review draft provider profiles'
);
select is(
  (
    select count(*)
    from api.audit_events
    where organization_id = '22222222-2222-4222-8222-222222222222'
  ),
  0::bigint,
  'security analyst audit access cannot cross tenants'
);
select lives_ok(
  $test$
    insert into api.exceptions (
      organization_id, exception_id, category, destination_id, action,
      reason_code, status, expires_at, created_by
    ) values (
      '11111111-1111-4111-8111-111111111111',
      'synthetic-exception',
      'EMAIL',
      'local_file',
      'warn',
      'approved-test-case',
      'draft',
      now() + interval '1 day',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'
    )
  $test$,
  'security analysts can draft structured exceptions'
);

select set_config(
  'request.jwt.claim.sub',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3',
  true
);
select is(
  (
    select role
    from api.memberships
    where user_id = (select auth.uid())
  ),
  'developer',
  'developer authority comes from the membership row'
);
select is(
  (select count(*) from api.provider_profile_versions),
  1::bigint,
  'developers see released profiles but not drafts'
);
select is(
  (select count(*) from api.devices),
  1::bigint,
  'developers see only their own devices'
);
select is(
  (select count(*) from api.exceptions),
  0::bigint,
  'developers cannot browse organizational exceptions'
);
select lives_ok(
  $test$
    insert into api.safe_feedback (
      organization_id, submitted_by, category, action, sensitivity,
      status_bucket, detector_version
    ) values (
      '11111111-1111-4111-8111-111111111111',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3',
      'EMAIL',
      'warn',
      'confidential',
      'expected',
      '0.9.0'
    )
  $test$,
  'developers can submit structured safe feedback'
);
select is(
  (
    select count(*)
    from api.provider_profiles
    where organization_id = '22222222-2222-4222-8222-222222222222'
  ),
  0::bigint,
  'developer provider access cannot cross tenants'
);

select * from finish();
rollback;
