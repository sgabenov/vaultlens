import { useEffect, useRef, useId, type ReactNode } from "react";

export default function CertificateDialog({ children, onClose, title = "Certificate details", busy = false }: {
  children: ReactNode;
  onClose: () => void;
  title?: string;
  busy?: boolean;
}) {
  const titleId = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current!;
    const previousFocus = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    element.showModal();
    document.body.style.overflow = "hidden";
    return () => {
      element.close();
      document.body.style.overflow = previousOverflow;
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
    };
  }, []);
  return (
    <dialog ref={dialog} className="pki-certificate-dialog" aria-labelledby={titleId}
      onCancel={(event) => { event.preventDefault(); if (!busy) onClose(); }}
      onClick={(event) => { if (!busy && event.target === event.currentTarget) onClose(); }}>
      <div className="pki-certificate-dialog-content">
        <header className="pki-row pki-spread">
          <h2 id={titleId}>{title}</h2>
          <button type="button" onClick={onClose} disabled={busy} aria-label={`Close ${title.toLowerCase()}`} autoFocus>Close</button>
        </header>
        {children}
      </div>
    </dialog>
  );
}
