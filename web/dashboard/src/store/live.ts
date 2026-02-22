import { create } from "zustand";

export type LiveEvent = {
  id: string;
  topic: string;
  severity: "critical" | "warning" | "info";
  message: string;
  timestamp: string;
  source?: string;
};

type LiveState = {
  alerts: LiveEvent[];
  audit: LiveEvent[];
  unreadAlerts: number;
  pushAlert: (item: LiveEvent) => void;
  pushAudit: (item: LiveEvent) => void;
  markAlertsRead: () => void;
};

const keepLatest = (items: LiveEvent[], max = 150): LiveEvent[] =>
  items.slice(0, max);

export const useLiveStore = create<LiveState>((set) => ({
  alerts: [],
  audit: [],
  unreadAlerts: 0,
  pushAlert: (item) =>
    set((state) => ({
      alerts: keepLatest([item, ...state.alerts]),
      unreadAlerts: state.unreadAlerts + 1
    })),
  pushAudit: (item) =>
    set((state) => ({
      audit: keepLatest([item, ...state.audit])
    })),
  markAlertsRead: () =>
    set(() => ({
      unreadAlerts: 0
    }))
}));
