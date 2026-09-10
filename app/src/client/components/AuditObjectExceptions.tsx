import AuditPagination from './AuditPagination';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getAuditRules,
  getAuditObjectExceptions,
  removeAuditObjectException,
  saveAuditObjectException,
  type AuditExceptionInput,
} from '../lib/api';
import type { AuditException } from '../../shared/securityAudit';
const empty: AuditExceptionInput = {
  rule_id: '',
  namespace: '',
  object_path: '',
  owner: '',
  reason: '',
  expires: '',
};
function errorText(error: unknown) {
  const e = error as {
    response?: { data?: { error?: string } };
    message?: string;
  } | null;
  return e?.response?.data?.error ?? e?.message;
}
export default function AuditObjectExceptions() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ['audit-object-exceptions'],
    queryFn: getAuditObjectExceptions,
  });
  const rules = useQuery({ queryKey: ['audit-rules'], queryFn: getAuditRules });
  const [search, setSearch] = useState(''),
    [status, setStatus] = useState('All'),
    [requested, setPage] = useState(1);
  const [editor, setEditor] = useState<{
    id?: string;
    value: AuditExceptionInput;
  } | null>(null);
  const [notice, setNotice] = useState('');
  const refresh = () =>
    client.invalidateQueries({ queryKey: ['audit-object-exceptions'] });
  const remove = useMutation({
    mutationFn: removeAuditObjectException,
    onSuccess: () => {
      refresh();
      setNotice(
        'Exception removed from future analyses. Historical results are unchanged.',
      );
    },
  });
  const save = useMutation({
    mutationFn: ({ value, id }: { value: AuditExceptionInput; id?: string }) =>
      saveAuditObjectException(value, id),
    onSuccess: () => {
      refresh();
      setEditor(null);
      setNotice(
        'Exception saved for future analyses. Reanalyze a snapshot to apply it.',
      );
    },
  });
  const now = new Date(),
    today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const matches =
    query.data?.filter(
      (entry) =>
        (status === 'All' ||
          (entry.expires < today ? 'Expired' : 'Active') === status) &&
        [
          entry.rule_id,
          entry.namespace,
          entry.object_path,
          entry.owner,
          entry.reason,
        ].some((value) => value.toLowerCase().includes(search.toLowerCase())),
    ) ?? [];
  const [size, setSize] = useState(10);
  const page = Math.min(
    requested,
    Math.max(1, Math.ceil(matches.length / size)),
  );
  function edit(entry?: AuditException) {
    save.reset();
    setNotice('');
    setEditor({
      id: entry?.id,
      value: entry
        ? {
            rule_id: entry.rule_id,
            namespace: entry.namespace,
            object_path: entry.object_path,
            owner: entry.owner,
            reason: entry.reason,
            expires: entry.expires,
          }
        : { ...empty },
    });
  }
  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Exceptions</h2>
        <button
          className="rounded bg-blue-600 px-4 py-2 text-sm text-white disabled:opacity-50"
          disabled={!!editor}
          onClick={() => edit()}
        >
          New exception
        </button>
      </div>
      <p className="text-sm text-gray-500">
        Accept a risk for one check and exact object. Collection and other
        checks continue. Historical results are unchanged.
      </p>
      {notice && (
        <p role="status" className="text-sm text-blue-700">
          {notice}
        </p>
      )}
      {editor && (
        <form
          className="space-y-3 rounded border p-4"
          onSubmit={(event) => {
            event.preventDefault();
            save.mutate(editor);
          }}
        >
          <h3 className="font-medium">
            {editor.id ? 'Edit exception' : 'New exception'}
          </h3>
          <label className="block text-sm">
            Check
            <select
              required
              disabled={save.isPending || rules.isPending || !!rules.error}
              className="mt-1 block w-full rounded border p-2"
              value={editor.value.rule_id}
              onChange={(event) =>
                setEditor({
                  ...editor,
                  value: { ...editor.value, rule_id: event.target.value },
                })
              }
            >
              <option value="">Select a built-in check</option>
              {rules.data?.catalog
                .filter((rule) => rule.source === 'builtin')
                .map((rule) => (
                  <option key={rule.id} value={rule.id}>
                    {rule.id} · {rule.title}
                  </option>
                ))}
            </select>
          </label>
          {rules.error && (
            <p role="alert" className="text-sm text-red-700">
              Could not load checks: {errorText(rules.error)}
            </p>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            {(['namespace', 'object_path', 'owner', 'expires'] as const).map(
              (key) => (
                <label key={key} className="text-sm">
                  {
                    {
                      namespace: 'Vault namespace (empty = root)',
                      object_path: 'Exact object API path',
                      owner: 'Owner',
                      expires: 'Expiry date',
                    }[key]
                  }
                  <input
                    required={key !== 'namespace'}
                    disabled={save.isPending}
                    type={key === 'expires' ? 'date' : 'text'}
                    min={key === 'expires' ? today : undefined}
                    maxLength={
                      key === 'owner' ? 200 : key === 'namespace' ? 1024 : 2048
                    }
                    placeholder={
                      key === 'object_path'
                        ? 'sys/policies/acl/default'
                        : undefined
                    }
                    className="mt-1 block w-full rounded border p-2"
                    value={editor.value[key]}
                    onChange={(event) =>
                      setEditor({
                        ...editor,
                        value: { ...editor.value, [key]: event.target.value },
                      })
                    }
                  />
                </label>
              ),
            )}
          </div>
          <p className="text-xs text-gray-500">
            Use the full object path shown in Findings. Wildcards are treated
            literally. For the root namespace, leave the namespace empty.
          </p>
          <label className="block text-sm">
            Reason
            <textarea
              required
              maxLength={2000}
              disabled={save.isPending}
              className="mt-1 block w-full rounded border p-2"
              value={editor.value.reason}
              onChange={(event) =>
                setEditor({
                  ...editor,
                  value: { ...editor.value, reason: event.target.value },
                })
              }
            />
          </label>
          {save.error && (
            <p role="alert" className="text-sm text-red-700">
              {errorText(save.error)}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              disabled={save.isPending}
              onClick={() => setEditor(null)}
              className="rounded border px-3 py-2 text-sm"
            >
              Cancel
            </button>
            <button
              disabled={save.isPending || rules.isPending || !!rules.error}
              className="rounded bg-blue-600 px-3 py-2 text-sm text-white disabled:opacity-50"
            >
              {save.isPending ? 'Saving…' : 'Save exception'}
            </button>
          </div>
        </form>
      )}
      <div className="flex flex-wrap gap-3">
        <label className="flex-1 text-sm">
          Search
          <input
            placeholder="Check, object, namespace, owner or reason"
            className="mt-1 block w-full rounded border p-2"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
          />
        </label>
        <label className="text-sm">
          Status
          <select
            className="mt-1 block rounded border p-2"
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              setPage(1);
            }}
          >
            {['All', 'Active', 'Expired'].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
      </div>
      {query.isPending && <p>Loading exceptions…</p>}
      {(query.error || remove.error) && (
        <p role="alert" className="text-sm text-red-700">
          {errorText(query.error || remove.error)}
        </p>
      )}
      {matches.slice((page - 1) * size, page * size).map((entry) => (
        <article
          key={entry.id}
          className="space-y-1 rounded border p-4 text-sm"
        >
          <h3 className="font-medium">
            {entry.rule_id} · {entry.expires < today ? 'Expired' : 'Active'}
          </h3>
          <p className="break-all font-mono text-xs">
            {entry.namespace || 'root'} · {entry.object_path}
          </p>
          <p>{entry.reason}</p>
          <p className="text-xs text-gray-500">
            {entry.owner} · expires {entry.expires}
          </p>
          <div className="flex gap-2 pt-2">
            <button
              className="rounded border px-3 py-1 disabled:opacity-50"
              disabled={!!editor || remove.isPending}
              onClick={() => edit(entry)}
            >
              Edit exception
            </button>
            <button
              className="rounded border px-3 py-1 disabled:opacity-50"
              disabled={!!editor || remove.isPending}
              onClick={() => remove.mutate(entry.id)}
            >
              Remove from future analyses
            </button>
          </div>
        </article>
      ))}
      {!query.isPending && !query.error && !matches.length && (
        <p className="text-sm text-gray-500">No matching exceptions.</p>
      )}
      <AuditPagination
        page={page}
        total={matches.length}
        size={size}
        onChange={setPage}
        onSizeChange={setSize}
      />
    </section>
  );
}
