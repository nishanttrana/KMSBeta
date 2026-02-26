import { ChevronLeft, ChevronRight } from "lucide-react";
import { groupLabels, type GroupId, type TabConfig, type TabId } from "../config/tabs";
import { cx } from "./primitives";

type SidebarProps = {
  tabsByGroup: Record<GroupId, TabConfig[]>;
  activeTab: TabId;
  onSelect: (tabId: TabId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
};

const groupOrder: GroupId[] = [
  "core",
  "secrets_certs",
  "cloud_integration",
  "data_protection",
  "infrastructure",
  "governance_compliance",
  "admin"
];

export function Sidebar(props: SidebarProps) {
  const { tabsByGroup, activeTab, onSelect, collapsed, onToggleCollapse } = props;

  return (
    <aside
      className={cx(
        "relative h-full border-r border-cyber-border bg-cyber-sidebar transition-all duration-200",
        collapsed ? "w-[56px]" : "w-[210px]"
      )}
    >
      <div className="border-b border-cyber-border px-2 py-3">
        <button
          onClick={onToggleCollapse}
          className={cx("flex w-full items-center gap-2 rounded-md px-1 text-left", collapsed ? "justify-center" : "justify-start")}
          aria-label="Toggle sidebar"
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-[linear-gradient(135deg,#06d6e0,#a78bfa)] text-xs font-bold text-cyber-bg">
            V
          </span>
          {!collapsed ? <span className="text-[13px] font-bold tracking-[0.16em] text-cyber-text">VECTA KMS</span> : null}
          {!collapsed ? (
            <span className="ml-auto text-cyber-muted">{collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}</span>
          ) : null}
        </button>
      </div>

      <div className="h-[calc(100%-52px)] overflow-auto py-1">
        <div className={cx("mb-1", collapsed && "text-center")}>
        </div>

        <nav className="space-y-2">
          {groupOrder.map((group) => {
            const tabs = tabsByGroup[group];
            if (!tabs?.length) {
              return null;
            }
            return (
              <section key={group} className="space-y-1">
                {!collapsed ? (
                  <h2 className="px-3 pt-2 text-[9px] font-bold uppercase tracking-[0.16em] text-cyber-muted">{groupLabels[group]}</h2>
                ) : null}
                <div className="space-y-0.5">
                  {tabs.map((tab) => {
                    const selected = activeTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => onSelect(tab.id)}
                        title={collapsed ? tab.label : undefined}
                        className={cx(
                          "flex w-full items-center gap-2 border-l-2 px-3 py-1.5 text-left transition-colors",
                          selected
                            ? "border-cyber-accent bg-cyber-accent/10 text-cyber-text"
                            : "border-transparent text-cyber-muted hover:bg-cyber-elevated/40 hover:text-cyber-text",
                          collapsed && "justify-center px-0"
                        )}
                      >
                        <span className={cx("text-[14px]", collapsed && "w-full text-center text-[16px]")}>{tab.emoji}</span>
                        {!collapsed ? (
                          <span className="min-w-0">
                            <span className="block truncate text-[11px] font-medium">{tab.label}</span>
                          </span>
                        ) : null}
                      </button>
                    );
                  })}
                </div>
              </section>
            );
          })}
        </nav>
      </div>
    </aside>
  );
}
