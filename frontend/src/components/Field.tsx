import { useId } from "react";
import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { AlertIcon } from "./Icons";

/** After a failed submit, move focus to the first invalid field (DESIGN.md "Field errors"). */
export function focusFirstInvalid(form: HTMLFormElement | null | undefined): void {
  requestAnimationFrame(() => form?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
}

interface FieldBits {
  label: ReactNode;
  hint?: ReactNode;
  error?: string;
}

function describedBy(hintId: string, errorId: string, hint: unknown, error: unknown) {
  return [hint ? hintId : "", error ? errorId : ""].filter(Boolean).join(" ") || undefined;
}

export function TextField({ label, hint, error, className, ...rest }: FieldBits & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className={["input", className ?? ""].join(" ")}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(`${id}-h`, `${id}-e`, hint, error)}
        {...rest}
      />
      {hint && (
        <span id={`${id}-h`} className="hint">
          {hint}
        </span>
      )}
      {error && (
        <span id={`${id}-e`} className="error">
          <AlertIcon size={14} /> {error}
        </span>
      )}
    </div>
  );
}

export function TextArea({ label, hint, error, ...rest }: FieldBits & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        className="textarea"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(`${id}-h`, `${id}-e`, hint, error)}
        {...rest}
      />
      {hint && (
        <span id={`${id}-h`} className="hint">
          {hint}
        </span>
      )}
      {error && (
        <span id={`${id}-e`} className="error">
          <AlertIcon size={14} /> {error}
        </span>
      )}
    </div>
  );
}

export interface Option {
  value: string;
  label: string;
}

/** A native select. Pass `label` for a visible label, or `aria-label` for a compact filter. */
export function Select({
  label,
  hint,
  error,
  options,
  dense,
  className,
  ...rest
}: Partial<FieldBits> & { options: Option[]; dense?: boolean } & SelectHTMLAttributes<HTMLSelectElement>) {
  const id = useId();
  const select = (
    <select
      id={id}
      className={["select", dense ? "select-dense" : "", className ?? ""].filter(Boolean).join(" ")}
      aria-invalid={error ? true : undefined}
      aria-describedby={describedBy(`${id}-h`, `${id}-e`, hint, error)}
      {...rest}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
  if (!label) return select;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {select}
      {hint && (
        <span id={`${id}-h`} className="hint">
          {hint}
        </span>
      )}
      {error && (
        <span id={`${id}-e`} className="error">
          <AlertIcon size={14} /> {error}
        </span>
      )}
    </div>
  );
}
