import { useEffect, useRef, useState } from "react";
import { SearchIcon } from "./Icons";

/** A search box whose value lives in the URL: typing is debounced (300 ms) into `onChange`, and
 *  a change from outside (back button, "Clear filters") replaces what is shown. */
export function SearchField({
  value,
  onChange,
  label,
  placeholder,
  maxLength,
}: {
  value: string;
  onChange: (q: string) => void;
  /** Visually hidden; the accessible name. */
  label: string;
  placeholder: string;
  maxLength: number;
}) {
  const [text, setText] = useState(value);
  const latest = useRef(onChange);
  latest.current = onChange;
  useEffect(() => setText(value), [value]);
  useEffect(() => {
    if (text.trim() === value) return;
    const t = setTimeout(() => latest.current(text.trim()), 300);
    return () => clearTimeout(t);
  }, [text, value]);
  return (
    <label className="search">
      <SearchIcon />
      <span className="visually-hidden">{label}</span>
      <input
        type="search"
        placeholder={placeholder}
        value={text}
        maxLength={maxLength}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape" && !text) e.currentTarget.blur();
        }}
      />
    </label>
  );
}
