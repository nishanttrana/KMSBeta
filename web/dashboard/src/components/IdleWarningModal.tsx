import { useEffect, useState } from "react";
import { C } from "./v3/theme";
import { Btn } from "./v3/legacyPrimitives";

type IdleWarningModalProps = {
  open: boolean;
  secondsRemaining: number;
  onStayActive: () => void;
  onLogout: () => void;
};

export function IdleWarningModal({ open, secondsRemaining, onStayActive, onLogout }: IdleWarningModalProps) {
  const [countdown, setCountdown] = useState(secondsRemaining);

  useEffect(() => {
    setCountdown(secondsRemaining);
  }, [secondsRemaining, open]);

  useEffect(() => {
    if (!open) return;
    if (countdown <= 0) {
      onLogout();
      return;
    }
    const timer = setTimeout(() => setCountdown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [open, countdown, onLogout]);

  if (!open) return null;

  const minutes = Math.floor(countdown / 60);
  const seconds = countdown % 60;
  const display = `${minutes}:${seconds.toString().padStart(2, "0")}`;
  const progress = countdown / secondsRemaining;

  // SVG circle for countdown
  const size = 100;
  const strokeWidth = 6;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - progress);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 2000,
      display: "flex", alignItems: "center", justifyContent: "center"
    }}>
      <div style={{
        position: "absolute", inset: 0,
        background: "rgba(0,0,0,.75)", backdropFilter: "blur(6px)"
      }} />
      <div style={{
        position: "relative", background: C.surface,
        border: `1px solid ${C.borderHi}`, borderRadius: 16,
        padding: "32px 40px", width: 380, textAlign: "center",
        boxShadow: "0 24px 60px rgba(0,0,0,.5)"
      }}>
        {/* Countdown ring */}
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 20 }}>
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
            <circle
              cx={size / 2} cy={size / 2} r={radius}
              fill="none" stroke={C.border} strokeWidth={strokeWidth}
            />
            <circle
              cx={size / 2} cy={size / 2} r={radius}
              fill="none" stroke="#f59e0b" strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
              style={{ transition: "stroke-dashoffset 1s linear" }}
            />
            <text
              x={size / 2} y={size / 2}
              textAnchor="middle" dominantBaseline="central"
              fill="#f59e0b" fontSize="22" fontWeight="700"
              fontFamily="monospace"
            >
              {display}
            </text>
          </svg>
        </div>

        <div style={{ fontSize: 15, fontWeight: 600, color: C.text, marginBottom: 8 }}>
          Session Timeout Warning
        </div>
        <div style={{ fontSize: 13, color: C.dim, marginBottom: 24, lineHeight: 1.5 }}>
          Your session will expire due to inactivity.
          <br />
          Click below to stay signed in.
        </div>

        <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
          <Btn onClick={onLogout} danger>
            Logout Now
          </Btn>
          <Btn onClick={onStayActive} primary>
            Stay Active
          </Btn>
        </div>
      </div>
    </div>
  );
}
