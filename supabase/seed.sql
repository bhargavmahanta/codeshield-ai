-- Synthetic local-only identities and metadata. No value in this file is a real credential.
insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) values
  (
    '00000000-0000-0000-0000-000000000000',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',
    'authenticated', 'authenticated', 'admin-a@example.invalid',
    extensions.crypt(gen_random_uuid()::text, extensions.gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}', now(), now()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2',
    'authenticated', 'authenticated', 'analyst-a@example.invalid',
    extensions.crypt(gen_random_uuid()::text, extensions.gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}', now(), now()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3',
    'authenticated', 'authenticated', 'developer-a@example.invalid',
    extensions.crypt(gen_random_uuid()::text, extensions.gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}', now(), now()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
    'authenticated', 'authenticated', 'admin-b@example.invalid',
    extensions.crypt(gen_random_uuid()::text, extensions.gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}', now(), now()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',
    'authenticated', 'authenticated', 'analyst-b@example.invalid',
    extensions.crypt(gen_random_uuid()::text, extensions.gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}', now(), now()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3',
    'authenticated', 'authenticated', 'developer-b@example.invalid',
    extensions.crypt(gen_random_uuid()::text, extensions.gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}', now(), now()
  )
on conflict (id) do nothing;

insert into auth.identities (
  provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at
)
select
  id::text,
  id,
  jsonb_build_object('sub', id::text, 'email', email),
  'email',
  now(),
  now(),
  now()
from auth.users
where email like '%@example.invalid'
on conflict (provider_id, provider) do nothing;

insert into api.organizations (id, slug, display_name) values
  ('11111111-1111-4111-8111-111111111111', 'synthetic-alpha', 'Synthetic Alpha'),
  ('22222222-2222-4222-8222-222222222222', 'synthetic-beta', 'Synthetic Beta')
on conflict (id) do nothing;

insert into api.memberships (organization_id, user_id, role) values
  ('11111111-1111-4111-8111-111111111111', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', 'administrator'),
  ('11111111-1111-4111-8111-111111111111', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', 'security_analyst'),
  ('11111111-1111-4111-8111-111111111111', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3', 'developer'),
  ('22222222-2222-4222-8222-222222222222', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1', 'administrator'),
  ('22222222-2222-4222-8222-222222222222', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2', 'security_analyst'),
  ('22222222-2222-4222-8222-222222222222', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3', 'developer')
on conflict (organization_id, user_id) do nothing;

insert into api.provider_profiles (
  id, organization_id, profile_id, display_name
) values
  (
    '11111111-aaaa-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    'synthetic-provider',
    'Synthetic Provider'
  ),
  (
    '22222222-bbbb-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    'synthetic-provider',
    'Synthetic Provider'
  )
on conflict (id) do nothing;

insert into api.provider_profile_versions (
  id, organization_id, provider_profile_id, version, status,
  profile_document, evidence_digest, created_by, released_at
) values
  (
    '11111111-a001-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    '11111111-aaaa-4111-8111-111111111111',
    1,
    'released',
    '{
      "profile_id":"synthetic-provider",
      "version":1,
      "data_types":["prompt","source"],
      "retention_days":0,
      "training":false,
      "human_review":false,
      "regions":["local"],
      "controls":["no-retention"],
      "source_ids":["synthetic-source"]
    }',
    repeat('a', 64),
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2',
    now()
  ),
  (
    '22222222-b001-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    '22222222-bbbb-4222-8222-222222222222',
    1,
    'released',
    '{
      "profile_id":"synthetic-provider",
      "version":1,
      "data_types":["prompt"],
      "retention_days":0,
      "training":false,
      "human_review":false,
      "regions":["local"],
      "controls":["no-retention"],
      "source_ids":["synthetic-source"]
    }',
    repeat('b', 64),
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',
    now()
  )
on conflict (id) do nothing;

insert into api.provider_sources (
  organization_id, provider_profile_version_id, source_id, source_kind,
  evidence_digest, reviewed_at
) values
  (
    '11111111-1111-4111-8111-111111111111',
    '11111111-a001-4111-8111-111111111111',
    'synthetic-source',
    'provider_documentation',
    repeat('c', 64),
    now()
  ),
  (
    '22222222-2222-4222-8222-222222222222',
    '22222222-b001-4222-8222-222222222222',
    'synthetic-source',
    'provider_documentation',
    repeat('d', 64),
    now()
  )
on conflict (provider_profile_version_id, source_id) do nothing;

insert into api.destinations (
  id, organization_id, destination_id, display_name
) values
  (
    '11111111-d001-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    'local_file',
    'Local file'
  ),
  (
    '22222222-d001-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    'local_file',
    'Local file'
  )
on conflict (id) do nothing;

insert into api.destination_versions (
  id, organization_id, destination_id, version, sensitivity_ceiling, status, settings
) values
  (
    '11111111-d101-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    '11111111-d001-4111-8111-111111111111',
    1, 'restricted', 'released', '{"local_only":true}'
  ),
  (
    '22222222-d101-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    '22222222-d001-4222-8222-222222222222',
    1, 'restricted', 'released', '{"local_only":true}'
  )
on conflict (id) do nothing;

insert into api.policies (
  id, organization_id, policy_id, display_name, mandatory
) values
  (
    '11111111-c001-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    'baseline',
    'Synthetic baseline',
    true
  ),
  (
    '22222222-c001-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    'baseline',
    'Synthetic baseline',
    true
  )
on conflict (id) do nothing;

insert into api.policy_versions (
  id, organization_id, policy_id, version, status, policy_document, created_by
) values
  (
    '11111111-c101-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    '11111111-c001-4111-8111-111111111111',
    1,
    'released',
    '{
      "name":"baseline",
      "description_code":"synthetic_baseline",
      "version":1,
      "rules":[{
        "rule_id":"restricted-block",
        "category":"API_KEY",
        "action":"block",
        "destination_id":"local_file",
        "sensitivity":"restricted",
        "mandatory":true,
        "remediation_code":"remove_secret",
        "enabled":true
      }]
    }',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'
  ),
  (
    '22222222-c101-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    '22222222-c001-4222-8222-222222222222',
    1,
    'released',
    '{
      "name":"baseline",
      "description_code":"synthetic_baseline",
      "version":1,
      "rules":[{
        "rule_id":"restricted-block",
        "category":"API_KEY",
        "action":"block",
        "destination_id":"local_file",
        "sensitivity":"restricted",
        "mandatory":true,
        "remediation_code":"remove_secret",
        "enabled":true
      }]
    }',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
  )
on conflict (id) do nothing;

insert into api.attestations (
  organization_id, attestation_id, provider_profile_version_id, status,
  evidence_digest, issued_at, expires_at
) values
  (
    '11111111-1111-4111-8111-111111111111',
    'synthetic-attestation',
    '11111111-a001-4111-8111-111111111111',
    'valid',
    repeat('e', 64),
    now(),
    now() + interval '30 days'
  ),
  (
    '22222222-2222-4222-8222-222222222222',
    'synthetic-attestation',
    '22222222-b001-4222-8222-222222222222',
    'valid',
    repeat('f', 64),
    now(),
    now() + interval '30 days'
  )
on conflict (organization_id, attestation_id) do nothing;

insert into api.devices (
  id, organization_id, device_id, display_name, owner_user_id
) values
  (
    '11111111-e001-4111-8111-111111111111',
    '11111111-1111-4111-8111-111111111111',
    'synthetic-device',
    'Synthetic device',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3'
  ),
  (
    '22222222-e001-4222-8222-222222222222',
    '22222222-2222-4222-8222-222222222222',
    'synthetic-device',
    'Synthetic device',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3'
  )
on conflict (id) do nothing;

insert into api.detector_versions (
  organization_id, detector_id, version, status
) values
  ('11111111-1111-4111-8111-111111111111', 'core', '0.9.0', 'supported'),
  ('22222222-2222-4222-8222-222222222222', 'core', '0.9.0', 'supported')
on conflict (organization_id, detector_id, version) do nothing;

insert into api.model_versions (
  organization_id, model_id, version, status
) values
  ('11111111-1111-4111-8111-111111111111', 'context-classifier', '0.9.0', 'supported'),
  ('22222222-2222-4222-8222-222222222222', 'context-classifier', '0.9.0', 'supported')
on conflict (organization_id, model_id, version) do nothing;
