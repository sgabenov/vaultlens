import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAuditRules, saveAuditRules } from '../lib/api';
import type { RuleSettings } from '../../shared/auditRules';
const example = `version: 1
rule:
  id: CUSTOM-TOKEN-TTL
  status: stable
  severity: medium
  finding_kind: risky_configuration
  title: Token TTL exceeds team threshold
  description: Review roles with an explicitly configured token lifetime above one hour.
  remediation: Reduce token_ttl to the reviewed team limit.
  object_types: [role]
  detector: field_compare
  parameters:
    field: token_ttl
    operator: greater_than
    value: 3600
`;
export default function AuditRulesPage() {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['audit-rules'], queryFn: getAuditRules });
  const [draft, setDraft] = useState<RuleSettings | null>(null);
  const [selected, setSelected] = useState('');
  const [filter, setFilter] = useState('');
  const [importError, setImportError] = useState('');
  const save = useMutation({
    mutationFn: saveAuditRules,
    onSuccess: (data) => {
      queryClient.setQueryData(['audit-rules'], data);
      setDraft(null);
    },
  });
  const settings = draft ?? query.data?.settings;
  const chosen = query.data?.catalog.find((r) => r.id === selected);
  const update = (field: 'configYaml' | 'customRulesYaml', value: string) => {
    if (settings) setDraft({ ...settings, [field]: value });
  };
  const error = save.error as {
    response?: { data?: { error?: string } };
    message?: string;
  } | null;
  async function importFile(file: File | undefined) {
    if (!file) return;
    if (file.size > 256000) {
      setImportError('Maximum YAML file size is 256 KB');
      return;
    }
    try {
      update('customRulesYaml', await file.text());
      setImportError('');
    } catch {
      setImportError('Could not read the selected file');
    }
  }
  return (
    <div className="space-y-5">
      <Link className="text-sm text-blue-700 underline" to="/security-audit">
        Back to audit
      </Link>
      <div>
        <h1 className="text-2xl font-semibold">
          Audit rules and configuration
        </h1>
        <p className="mt-2 text-sm text-gray-600">
          Built-in definitions are immutable. Configure profiles and overrides,
          or add YAML rules backed by registered detectors.
        </p>
      </div>
      {query.error && (
        <p role="alert">
          Could not load rules. Administrator access is required.
        </p>
      )}
      {settings && (
        <>
          <div className="flex items-center gap-4">
            <span className="text-sm">
              Saved revision {query.data?.settings.revision} ·{' '}
              {query.data?.catalog.length} definitions
            </span>
            <button
              disabled={!draft || save.isPending}
              onClick={() => save.mutate(settings)}
              className="rounded bg-blue-600 px-4 py-2 text-sm text-white disabled:opacity-50"
            >
              {save.isPending ? 'Saving…' : 'Save configuration'}
            </button>
            {draft && (
              <button
                className="text-sm underline"
                onClick={() => {
                  setDraft(null);
                  save.reset();
                }}
              >
                Discard edits
              </button>
            )}
          </div>
          {(error || importError) && (
            <p
              role="alert"
              className="rounded bg-red-50 p-3 text-sm text-red-800"
            >
              {importError || error?.response?.data?.error || error?.message}
            </p>
          )}
          {save.isSuccess && !draft && (
            <p role="status" className="text-sm text-green-700">
              Saved. New runs use this revision; previous runs retain their
              configuration.
            </p>
          )}
          <div className="grid gap-5 lg:grid-cols-2">
            <section>
              <label htmlFor="audit-config" className="font-medium">
                Environment configuration (YAML)
              </label>
              <textarea
                id="audit-config"
                spellCheck={false}
                value={settings.configYaml}
                onChange={(e) => update('configYaml', e.target.value)}
                className="mt-2 h-80 w-full rounded border bg-white p-3 font-mono text-xs"
              />
              <p className="mt-1 text-xs text-gray-600">
                Use rules.RULE-ID.enabled and rules.RULE-ID.severity for
                overrides. Threshold keys follow the Python configuration
                format.
              </p>
            </section>
            <section>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label htmlFor="audit-custom-rules" className="font-medium">
                  Custom rule definitions (YAML)
                </label>
                <button
                  className="text-sm text-blue-700 underline"
                  onClick={() =>
                    update(
                      'customRulesYaml',
                      settings.customRulesYaml.trim()
                        ? settings.customRulesYaml + '\n---\n' + example
                        : example,
                    )
                  }
                >
                  Append example
                </button>
              </div>
              <textarea
                id="audit-custom-rules"
                spellCheck={false}
                value={settings.customRulesYaml}
                onChange={(e) => update('customRulesYaml', e.target.value)}
                className="mt-2 h-80 w-full rounded border bg-white p-3 font-mono text-xs"
              />
              <label className="text-xs">
                Import YAML into editor{' '}
                <input
                  type="file"
                  accept=".yaml,.yml"
                  onChange={(e) => void importFile(e.target.files?.[0])}
                />
              </label>
              <p className="mt-2 text-xs text-gray-600">
                One version: 1 / rule: document per rule; separate documents
                with ---. Imported text is validated on save. No JavaScript or
                arbitrary expressions are executed.
              </p>
            </section>
          </div>
          <div className="rounded border border-amber-200 bg-amber-50 p-3 text-sm">
            The catalog includes the Python reference definitions. Pending
            detectors are visible and produce coverage gaps when enabled, until
            their native implementation is verified.
          </div>
          <label className="block text-sm">
            Filter catalog{' '}
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="ml-2 rounded border p-2"
              placeholder="Rule ID, title or detector"
            />
          </label>
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="max-h-96 overflow-auto rounded border bg-white">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr>
                    <th className="p-2">Rule</th>
                    <th>Severity</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data?.catalog
                    .filter((r) =>
                      (r.id + ' ' + r.title + ' ' + r.detector)
                        .toLowerCase()
                        .includes(filter.toLowerCase()),
                    )
                    .map((r) => (
                      <tr key={r.id} className="border-t">
                        <td className="p-2">
                          <button
                            onClick={() => setSelected(r.id)}
                            className="text-blue-700 underline"
                          >
                            {r.id}
                          </button>
                          <div className="text-xs text-gray-500">{r.title}</div>
                        </td>
                        <td>{r.effectiveSeverity}</td>
                        <td>
                          {r.active ? 'Enabled' : 'Disabled'} ·{' '}
                          {r.supported ? 'Available' : 'Pending'}
                          <div className="text-xs">
                            {r.source} · {r.status}
                          </div>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
            <div className="min-w-0 rounded border bg-white p-3">
              {chosen ? (
                <>
                  <h2 className="font-medium">
                    {chosen.id}: {chosen.title}
                  </h2>
                  <p className="my-2 text-sm">{chosen.description}</p>
                  <pre className="max-h-96 overflow-auto whitespace-pre-wrap text-xs">
                    {chosen.yaml}
                  </pre>
                </>
              ) : (
                <p className="text-sm text-gray-500">
                  Select a rule to inspect its definition and detector
                  parameters.
                </p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
