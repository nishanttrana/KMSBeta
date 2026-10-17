import { useEffect, useRef, useState, type Dispatch, type RefObject, type SetStateAction } from "react";

// State for a popover anchored in the element the returned ref is put on (its
// trigger and its panel): it closes on a press outside that element or on
// Escape, not only on a second press of its trigger (13.12.0-beta).
export function usePopover<T extends HTMLElement = HTMLDivElement>(): [boolean, Dispatch<SetStateAction<boolean>>, RefObject<T | null>] {
  const [open, setOpen] = useState(false);
  const ref = useRef<T | null>(null);
  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);
  return [open, setOpen, ref];
}
