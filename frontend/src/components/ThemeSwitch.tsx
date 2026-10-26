import type { ReactNode } from "react";
import { setTheme, THEMES, useTheme } from "../lib/theme";
import type { Theme } from "../lib/theme";
import { MoonIcon, SunIcon, SystemThemeIcon } from "./Icons";

const OPTIONS: Record<Theme, { label: string; icon: ReactNode }> = {
  system: { label: "System", icon: <SystemThemeIcon /> },
  light: { label: "Light", icon: <SunIcon /> },
  dark: { label: "Dark", icon: <MoonIcon /> },
};

/** System / Light / Dark as a radio group of icon buttons. */
export function ThemeSwitch() {
  const theme = useTheme();
  return (
    <div className="theme-switch" role="radiogroup" aria-label="Theme">
      {THEMES.map((t) => (
        <button
          key={t}
          type="button"
          role="radio"
          aria-checked={theme === t}
          aria-label={OPTIONS[t].label}
          title={OPTIONS[t].label}
          onClick={() => setTheme(t)}
        >
          {OPTIONS[t].icon}
        </button>
      ))}
    </div>
  );
}
