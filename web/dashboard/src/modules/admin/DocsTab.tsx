import { useMemo, useState } from "react";
import { DOC_CAPABILITIES, DOC_COMPONENTS } from "../../components/v3/constants";
import { B, Card, Inp, Row2, Section } from "../../components/v3/legacyPrimitives";
import { C } from "../../components/v3/theme";

export const DocsTab = () => {
  const [query, setQuery] = useState("");

  const filteredComponents = useMemo(() => {
    const q = String(query || "").trim().toLowerCase();
    if (!q) {
      return DOC_COMPONENTS;
    }
    return DOC_COMPONENTS.filter((entry) => {
      return [entry.name, entry.group, entry.purpose, entry.customer].some((value) =>
        String(value || "").toLowerCase().includes(q)
      );
    });
  }, [query]);

  const filteredCapabilities = useMemo(() => {
    const q = String(query || "").trim().toLowerCase();
    if (!q) {
      return DOC_CAPABILITIES;
    }
    return DOC_CAPABILITIES.filter((entry) => {
      return [entry.name, entry.domain, entry.summary, entry.customer].some((value) =>
        String(value || "").toLowerCase().includes(q)
      );
    });
  }, [query]);

  return (
    <div>
      <Section title="Customer Documentation">
        <Card>
          <div style={{ fontSize: 10, color: C.dim }}>
            Static customer-facing component and capability reference. Operational and mutable controls remain in system/user/tenant administration tabs.
          </div>
        </Card>
        <div style={{ height: 8 }} />
        <Inp
          placeholder="Search components/capabilities..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <div style={{ height: 8 }} />
        <Row2>
          <Card style={{ maxHeight: 520, overflowY: "auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Components</div>
              <B c="blue">{`${filteredComponents.length} items`}</B>
            </div>
            <div style={{ display: "grid", gap: 8 }}>
              {filteredComponents.map((entry) => (
                <Card key={entry.name}>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{entry.name}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>{entry.group}</div>
                  <div style={{ fontSize: 10, color: C.dim }}>{entry.purpose}</div>
                  <div style={{ fontSize: 10, color: C.text }}>{entry.customer}</div>
                </Card>
              ))}
              {!filteredComponents.length ? <Card><div style={{ fontSize: 10, color: C.muted }}>No matching components.</div></Card> : null}
            </div>
          </Card>

          <Card style={{ maxHeight: 520, overflowY: "auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Capabilities</div>
              <B c="blue">{`${filteredCapabilities.length} items`}</B>
            </div>
            <div style={{ display: "grid", gap: 8 }}>
              {filteredCapabilities.map((entry) => (
                <Card key={entry.name}>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{entry.name}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>{entry.domain}</div>
                  <div style={{ fontSize: 10, color: C.dim }}>{entry.summary}</div>
                  <div style={{ fontSize: 10, color: C.text }}>{entry.customer}</div>
                </Card>
              ))}
              {!filteredCapabilities.length ? <Card><div style={{ fontSize: 10, color: C.muted }}>No matching capabilities.</div></Card> : null}
            </div>
          </Card>
        </Row2>
      </Section>
    </div>
  );
};
