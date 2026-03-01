import {
  DataEncryptionTab as LocalDataEncryptionTab,
  DataProtectionTab as LocalDataProtectionTab,
  TokenizeTab as LocalTokenizeTab
} from "./TokenizeTab";

type BridgeProps = {
  session: any;
  keyCatalog?: any[];
  onToast?: (message: string) => void;
  subView?: string;
  onSubViewChange?: (next: string) => void;
  [key: string]: any;
};

const LocalTokenize = LocalTokenizeTab as any;
const LocalDataEncryption = LocalDataEncryptionTab as any;
const LocalDataProtection = LocalDataProtectionTab as any;

export const TokenizeTab = (props: BridgeProps) => <LocalTokenize {...props} />;

export const DataEncryptionTab = (props: BridgeProps) => <LocalDataEncryption {...props} />;

export const DataProtectionTab = (props: BridgeProps) => <LocalDataProtection {...props} />;
