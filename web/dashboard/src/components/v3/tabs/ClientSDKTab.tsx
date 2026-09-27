import { useEffect, useState } from "react";
import { downloadEKMSDK, getEKMSDKOverview } from "../../../lib/ekm";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Section } from "../legacyPrimitives";

// The client SDK Vecta ships: the Java JCA provider (source). There is no
// PKCS#11 module, and SDK usage is not observed, so no telemetry is shown.
export const ClientSDKTab = ({ session, onToast }: any) => {
  const [provider, setProvider] = useState<any>(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (!session?.token) return;
    getEKMSDKOverview(session, String(session?.tenantId || ""))
      .then((out: any) => setProvider((Array.isArray(out?.providers) ? out.providers : []).find((p: any) => p?.id === "jca") || null))
      .catch((error: any) => onToast?.(`SDK load failed: ${errMsg(error)}`));
  }, [session, onToast]);

  const download = async () => {
    setDownloading(true);
    try {
      const out: any = await downloadEKMSDK(session, "jca", "all", String(session?.tenantId || ""));
      const raw = atob(String(out?.content || ""));
      const bytes = Uint8Array.from(raw, (ch) => ch.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes], { type: String(out?.content_type || "application/zip") }));
      const a = document.createElement("a");
      a.href = url;
      a.download = String(out?.filename || "vecta-jca-sdk-all.zip");
      a.click();
      URL.revokeObjectURL(url);
      onToast?.("Java SDK downloaded.");
    } catch (error: any) {
      onToast?.(`SDK download failed: ${errMsg(error)}`);
    } finally {
      setDownloading(false);
    }
  };

  return <Section title="Java SDK">
    <Card style={{ padding: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <div style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>{String(provider?.name || "Java JCA/JCE Provider")}</div>
        <B c="blue">{String(provider?.status || "available")}</B>
      </div>
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 8 }}>
        Source for the JCA provider (services/jca-provider). Build with Maven and register com.vecta.kms.VectaKMSProvider.
        {provider?.size_label ? ` Download size ${provider.size_label}.` : ""}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
        {(Array.isArray(provider?.capabilities) ? provider.capabilities : []).map((c: string) => <B key={c} c="green">{c}</B>)}
      </div>
      <Btn small primary onClick={() => void download()} disabled={downloading || !session?.token}>{downloading ? "Downloading..." : "Download Java SDK"}</Btn>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 10 }}>
        Vecta does not ship a PKCS#11 module. Reach keys through the REST API, the KMIP server (port 5696, mTLS) or this provider.
      </div>
    </Card>
  </Section>;
};
