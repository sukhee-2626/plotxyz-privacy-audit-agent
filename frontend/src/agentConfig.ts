export type FieldType = "text" | "textarea" | "number" | "checkbox";

export interface AgentField {
  name: string;
  label: string;
  type: FieldType;
  rows?: number;
  placeholder?: string;
}

export interface AgentConfig {
  slug: string;
  title: string;
  tagline: string;
  purpose: string;
  accent: string;
  features: string[];
  limitations: string[];
  fields: AgentField[];
  sample: Record<string, string | number | boolean>;
  repo: string;
}

export const agent: AgentConfig = {
  "slug": "plotxyz-privacy-audit-agent",
  "title": "Privacy Audit",
  "tagline": "Find the privacy risks hiding in plain text.",
  "purpose": "Scans configuration and data-flow descriptions for credentials, personal data, plain HTTP, telemetry, and payload logging, then ranks findings by severity.",
  "accent": "#f472b6",
  "features": [
    "Pattern-based privacy checks",
    "Severity-ranked findings",
    "Heuristic risk score"
  ],
  "limitations": [
    "Static text heuristics are not a compliance certification.",
    "The agent does not inspect live systems or network traffic."
  ],
  "fields": [
    {
      "name": "config",
      "label": "Configuration text",
      "type": "textarea",
      "rows": 6,
      "placeholder": ""
    },
    {
      "name": "data_flow",
      "label": "Data-flow description",
      "type": "textarea",
      "rows": 5,
      "placeholder": ""
    }
  ],
  "sample": {
    "config": "telemetry: true\nlog_payload: true\napi_url: http://api.example.com\ncontact: ada@example.com",
    "data_flow": "Browser sends email and password to the API, which logs the request body and forwards it to analytics."
  },
  "repo": "https://github.com/sukhee-2626/plotxyz-privacy-audit-agent"
};
