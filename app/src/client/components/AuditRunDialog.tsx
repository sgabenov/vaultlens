import { useEffect, useRef, type ReactNode } from 'react';
export default function AuditRunDialog({
  open,
  onClose,
  onStart,
  busy,
  disabled,
  error,
  children,
}: {
  open: boolean;
  onClose: () => void;
  onStart: () => void;
  busy: boolean;
  disabled: boolean;
  error?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (open && !dialog?.open) dialog?.showModal();
    if (!open && dialog?.open) dialog.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      aria-labelledby="audit-run-title"
      className="m-auto max-h-[85vh] w-[calc(100%_-_2rem)] max-w-2xl overflow-y-auto rounded-lg border border-gray-200 bg-white p-6 text-gray-900 shadow-xl backdrop:bg-black/40"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
    >
      <form
        onInvalid={(event) => {
          const field = event.target as HTMLInputElement;
          const section = field.closest('details');
          if (section) section.open = true;
        }}
        onSubmit={(event) => {
          event.preventDefault();
          if (!disabled) onStart();
        }}
        className="space-y-5"
      >
        <div>
          <h2 id="audit-run-title" className="text-lg font-semibold">
            Collect and run audit
          </h2>
          <p className="mt-1 text-sm text-gray-500">
            Read configuration using your current VaultLens session.
          </p>
        </div>
        {children}
        {error && (
          <p role="alert" className="text-sm text-red-700">
            {error}
          </p>
        )}
        <footer className="flex justify-end gap-3 border-t pt-4">
          <button
            type="button"
            className="rounded border px-4 py-2 text-sm disabled:opacity-50"
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="rounded bg-blue-600 px-4 py-2 text-sm text-white disabled:opacity-50"
            disabled={disabled}
          >
            {busy ? 'Starting…' : 'Start collection'}
          </button>
        </footer>
      </form>
    </dialog>
  );
}
