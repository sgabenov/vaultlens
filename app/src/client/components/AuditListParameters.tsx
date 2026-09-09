import { useState } from 'react';
import type { CheckGroup } from '../../shared/auditCheckGroups';

type Change = { path: string[]; value: unknown };
type Props = {
  group: CheckGroup;
  configuration: Record<string, unknown>;
  disabled: boolean;
  onChange: (changes: Change[]) => void;
};

function StringList({
  label,
  values,
  disabled,
  onChange,
}: {
  label: string;
  values: string[];
  disabled: boolean;
  onChange: (values: string[]) => void;
}) {
  // Keep blank lines while typing; only normalized entries enter configuration.
  const [text, setText] = useState(values.join('\n'));
  return (
    <label className="block text-sm">
      {label}
      <textarea
        rows={3}
        className="mt-1 block w-full rounded border p-2 font-mono text-xs"
        disabled={disabled}
        value={text}
        onChange={(event) => {
          setText(event.target.value);
          onChange([
            ...new Set(
              event.target.value
                .split('\n')
                .map((item) => item.trim())
                .filter(Boolean),
            ),
          ]);
        }}
      />
    </label>
  );
}

export default function AuditListParameters({
  group,
  configuration,
  disabled,
  onChange,
}: Props) {
  const [mount, setMount] = useState('');
  const [error, setError] = useState('');
  const section = (name: string) =>
    (configuration[name] ?? {}) as Record<string, unknown>;
  const lists =
    group === 'JWT / OIDC'
      ? [
          {
            section: 'jwt',
            key: 'broad_globs',
            label: 'Claim values considered broad',
            fallback: ['*'],
          },
          {
            section: 'jwt',
            key: 'review_only_glob_claims',
            label:
              'Claims requiring review only when another claim restricts access',
            fallback: ['ref_protected'],
          },
        ]
      : group === 'Kubernetes'
        ? [
            {
              section: 'kubernetes',
              key: 'allowed_wildcard_namespaces',
              label:
                'Kubernetes namespaces allowed to use wildcard service accounts',
              fallback: [],
            },
          ]
        : [];
  const required = (section('jwt').required_bound_claims_by_mount ??
    {}) as Record<string, string[]>;
  return (
    <>
      {!!lists.length && (
        <details className="rounded border p-4">
          <summary className="cursor-pointer text-sm font-medium">
            {group} parameters
          </summary>
          <p className="mt-2 text-xs text-gray-500">
            One value per line. These settings apply to enabled detectors in
            this category.
          </p>
          <div className="mt-3 space-y-3">
            {lists.map((item) => (
              <StringList
                key={item.key}
                label={item.label}
                values={
                  (section(item.section)[item.key] ?? item.fallback) as string[]
                }
                disabled={disabled}
                onChange={(values) =>
                  onChange([{ path: [item.section, item.key], value: values }])
                }
              />
            ))}
          </div>
          {group === 'JWT / OIDC' && (
            <div className="mt-5 space-y-3">
              <h3 className="text-sm font-medium">
                Required bound claims by auth mount
              </h3>
              <p className="text-xs text-gray-500">
                Use the exact mount name such as oidc, without the auth/ prefix
                or trailing slash. Each entry lists claim names that roles must
                bind.
              </p>
              {Object.entries(required).map(([name, values]) => (
                <div key={name} className="rounded border p-3">
                  <StringList
                    label={`Required claims: ${name}`}
                    values={values}
                    disabled={disabled}
                    onChange={(claims) =>
                      onChange([
                        {
                          path: ['jwt', 'required_bound_claims_by_mount'],
                          value: { ...required, [name]: claims },
                        },
                      ])
                    }
                  />
                  <button
                    type="button"
                    className="mt-2 text-sm text-red-700"
                    disabled={disabled}
                    onClick={() => {
                      const next = { ...required };
                      delete next[name];
                      onChange([
                        {
                          path: ['jwt', 'required_bound_claims_by_mount'],
                          value: next,
                        },
                      ]);
                    }}
                  >
                    Remove mount {name}
                  </button>
                </div>
              ))}
              <div className="flex flex-wrap items-end gap-2">
                <label className="text-sm">
                  Auth mount
                  <input
                    className="mt-1 block rounded border p-2"
                    value={mount}
                    disabled={disabled}
                    onChange={(event) => {
                      setMount(event.target.value);
                      setError('');
                    }}
                  />
                </label>
                <button
                  type="button"
                  className="rounded border px-3 py-2 text-sm"
                  disabled={disabled}
                  onClick={() => {
                    const name = mount
                      .trim()
                      .replace(/^\/+|\/+$/g, '')
                      .replace(/^auth\//, '');
                    if (!name) {
                      setError('Enter an exact auth mount name.');
                      return;
                    }
                    if (Object.prototype.hasOwnProperty.call(required, name)) {
                      setError('This mount already has an entry.');
                      return;
                    }
                    onChange([
                      {
                        path: ['jwt', 'required_bound_claims_by_mount'],
                        value: { ...required, [name]: [] },
                      },
                    ]);
                    setMount('');
                    setError('');
                  }}
                >
                  Add mount
                </button>
              </div>
              {error && (
                <p role="alert" className="text-sm text-red-700">
                  {error}
                </p>
              )}
            </div>
          )}
        </details>
      )}
      <details className="rounded border p-4">
        <summary className="cursor-pointer text-sm font-medium">
          Privileged policy selectors
        </summary>
        <p className="mt-2 text-xs text-gray-500">
          Shared by assignment and authentication checks. These identify
          privileged policies; they do not exclude policies from analysis.
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <StringList
            label="Exact policy names"
            values={
              (section('privileged_policies').exact ?? [
                'root',
                'vault-admins',
              ]) as string[]
            }
            disabled={disabled}
            onChange={(values) =>
              onChange([
                { path: ['privileged_policies', 'exact'], value: values },
              ])
            }
          />
          <StringList
            label="Policy name patterns"
            values={(section('privileged_policies').patterns ?? []) as string[]}
            disabled={disabled}
            onChange={(values) =>
              onChange([
                { path: ['privileged_policies', 'patterns'], value: values },
              ])
            }
          />
        </div>
      </details>
    </>
  );
}
