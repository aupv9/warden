import { useEffect, useRef, useState } from "react";
import { Button } from "./Button";
import { CheckIcon, CopyIcon } from "./Icons";

/** Copies `text` to the clipboard. The result is announced in a polite live region next to the
 *  button ("Copied" / how to copy by hand), and `onFailed` lets the caller select the text so
 *  ⌘C / Ctrl+C works when the Clipboard API is unavailable (non-secure context, denied). The
 *  text is never logged. */
export function CopyButton({
  text,
  label = "Copy",
  copiedText = "Copied to the clipboard.",
  onFailed,
  size = "sm",
  variant = "ghost",
}: {
  text: string;
  label?: string;
  copiedText?: string;
  onFailed?: () => void;
  size?: "sm" | "md";
  variant?: "ghost" | "primary";
}) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async () => {
    clearTimeout(timer.current);
    try {
      if (!navigator.clipboard?.writeText) throw new Error("no clipboard");
      await navigator.clipboard.writeText(text);
      setStatus("copied");
      timer.current = setTimeout(() => setStatus("idle"), 4000);
    } catch {
      setStatus("failed");
      onFailed?.();
    }
  };

  return (
    <span className="copy-wrap">
      <Button size={size} variant={variant} onClick={() => void copy()}>
        {status === "copied" ? <CheckIcon size={14} /> : <CopyIcon />}
        {status === "copied" ? "Copied" : label}
      </Button>
      <span className={status === "failed" ? "copy-status error-text" : "copy-status"} role="status" aria-live="polite">
        {status === "copied" ? <span className="visually-hidden">{copiedText}</span> : null}
        {status === "failed" ? "Couldn't copy. The text is selected: press ⌘C or Ctrl+C." : null}
      </span>
    </span>
  );
}
