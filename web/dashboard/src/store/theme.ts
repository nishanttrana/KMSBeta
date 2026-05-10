import { create } from "zustand";

export type ThemeMode = "dark" | "light";

const STORAGE_KEY = "vecta.theme";

function detectSystemTheme(): ThemeMode {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function loadInitialTheme(): ThemeMode {
  if (typeof window === "undefined") return "dark";
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (saved === "dark" || saved === "light") return saved;
  return detectSystemTheme();
}

export function applyTheme(theme: ThemeMode): void {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-theme", theme);
}

type ThemeState = {
  theme: ThemeMode;
  setTheme: (next: ThemeMode) => void;
  toggle: () => void;
};

export const useTheme = create<ThemeState>((set, get) => ({
  theme: loadInitialTheme(),
  setTheme: (next) => {
    if (next === get().theme) return;
    set({ theme: next });
    applyTheme(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // localStorage unavailable (private mode) — non-fatal.
    }
  },
  toggle: () => {
    const next: ThemeMode = get().theme === "dark" ? "light" : "dark";
    get().setTheme(next);
  },
}));
