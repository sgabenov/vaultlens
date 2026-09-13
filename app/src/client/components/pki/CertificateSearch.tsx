import { pkiSearchFields } from "../../../shared/pki";
import type { PkiCondition } from "../../../shared/pki";
export default function CertificateSearch({
  conditions,
  onChange,
  match,
  onMatch,
  onSearch,
  disabled,
}: {
  conditions: PkiCondition[];
  onChange: (v: PkiCondition[]) => void;
  match: "all" | "any";
  onMatch: (v: "all" | "any") => void;
  onSearch: () => void;
  disabled: boolean;
}) {
  const change = (index: number, patch: Partial<PkiCondition>) =>
    onChange(conditions.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  return (
    <form
      className="pki-box"
      onSubmit={(e) => {
        e.preventDefault();
        onSearch();
      }}
    >
      <div className="pki-row pki-spread">
        <h2>Search by field</h2>
        <label>
          Match{" "}
          <select
            value={match}
            onChange={(e) => onMatch(e.target.value as "all" | "any")}
          >
            <option value="all">All conditions (AND)</option>
            <option value="any">Any condition (OR)</option>
          </select>
        </label>
      </div>
      {conditions.map((c, i) => (
        <div className="pki-condition" key={i}>
          <select
            aria-label={`Search field ${i + 1}`}
            value={c.field}
            onChange={(e) =>
              change(i, {
                field: e.target.value,
                operator: pkiSearchFields[e.target.value].operators[0],
                value: "",
              })
            }
          >
            {Object.entries(pkiSearchFields).map(([key, v]) => (
              <option key={key} value={key}>
                {v.label}
              </option>
            ))}
          </select>
          <select
            aria-label={`Search operator ${i + 1}`}
            value={c.operator}
            onChange={(e) => change(i, { operator: e.target.value })}
          >
            {pkiSearchFields[c.field].operators.map((op) => (
              <option key={op} value={op}>
                {
                  {
                    equals: "equals",
                    contains: "contains",
                    prefix: "starts with",
                    lt: "less than / before",
                    gt: "greater than / after",
                  }[op]
                }
              </option>
            ))}
          </select>
          <input
            aria-label={`Search value ${i + 1}`}
            type={
              ["notBefore", "notAfter"].includes(c.field)
                ? "date"
                : c.field === "keySize"
                  ? "number"
                  : "text"
            }
            placeholder="Enter a value"
            value={c.value}
            onChange={(e) => change(i, { value: e.target.value })}
          />
          <button
            type="button"
            aria-label={`Remove condition ${i + 1}`}
            onClick={() => onChange(conditions.filter((_, n) => n !== i))}
          >
            ×
          </button>
        </div>
      ))}
      <div className="pki-row pki-spread">
        <button
          type="button"
          disabled={conditions.length >= 12}
          onClick={() =>
            onChange([
              ...conditions,
              { field: "cn", operator: "contains", value: "" },
            ])
          }
        >
          + Add condition
        </button>
        <div className="pki-row">
          <button
            type="button"
            onClick={() =>
              onChange([{ field: "cn", operator: "contains", value: "" }])
            }
          >
            Clear conditions
          </button>
          <button className="pki-primary" disabled={disabled}>
            Search
          </button>
        </div>
      </div>
    </form>
  );
}
