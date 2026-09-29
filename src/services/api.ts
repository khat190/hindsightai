import {
  auditEvents,
  experienceRecords,
  playbookProposals,
  playbooks,
  responseActions,
} from "@/data/mock-data";

import type {
  AuditEvent,
  ExperienceRecord,
  Incident,
  IncidentStatus,
  Playbook,
  PlaybookProposal,
  ResponseAction,
} from "@/types/incident";

const API_BASE_URL = "http://127.0.0.1:8000";

const ACTIVE: IncidentStatus[] = [
  "detected",
  "investigating",
  "awaiting_approval",
  "executing",
];

type BackendIncident = {
  incident_id?: string;
  id?: string;
  incident_type?: string;
  type?: string;
  summary?: string;

  affected_user?: string;
  affected_host?: string;
  hosts?: string[];
  indicators?: string[];

  source?: string;
  reported_at?: string;

  telemetry?: {
    user_profiles?: Record<
      string,
      {
        role?: string;
        privileged?: boolean;
        usual_locations?: string[];
        dependent_services?: string[];
      }
    >;

    authentication_history?: Record<string, any[]>;
    user_activity?: Record<string, any[]>;
    active_sessions?: Record<string, any[]>;
    unauthorized_access?: Record<string, string[]>;

    indicators?: Record<
      string,
      {
        reputation?: string;
        tags?: string[];
        first_seen?: string;
      }
    >;

    logs?: any[];
  };
};

type BackendIncidentListResponse =
  | BackendIncident[]
  | {
      value?: BackendIncident[];
      Count?: number;
    };

type BackendPlaybook = {
  name: string;
  incident_type: string;
  version: string;
  status: string;
  description: string;

  steps: Array<{
    id: string;
    name: string;
    objective: string;
    actions?: string[];
    evidence?: string[];
    requires_approval: boolean;
    tools?: string[];
  }>;

  containment?: {
    strategy: string;
    options: Array<{
      tool: string;
      when: string;
      impact: string;
    }>;
  };

  eradication?: string[];
  recovery?: string[];
  post_incident?: string[];
};

function incidentTypeToCategory(
  type: string,
): Incident["category"] {
  switch (type) {
    case "phishing":
      return "Phishing";

    case "account_compromise":
    case "credential_compromise":
      return "Credential compromise";

    case "suspicious_login":
      return "Authentication anomaly";

    case "malware":
      return "Malware";

    case "data_exfiltration":
      return "Data exfiltration";

    default:
      return "Unauthorized access";
  }
}

function incidentTypeToPlaybook(
  type: string,
): string {
  switch (type) {
    case "phishing":
      return "pb-phish";

    case "account_compromise":
    case "credential_compromise":
      return "pb-cred";

    case "malware":
      return "pb-malware";

    case "data_exfiltration":
      return "pb-exfil";

    case "suspicious_login":
      return "pb-login";

    default:
      return "pb-access";
  }
}

function indicatorType(
  value: string,
): "ip" | "domain" {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)
    ? "ip"
    : "domain";
}

function backendIncidentToFrontend(
  incident: BackendIncident,
): Incident {
  const incidentId =
    incident.incident_id ??
    incident.id ??
    "unknown";

  const incidentType =
    incident.incident_type ??
    incident.type ??
    "unknown";

  const summary =
    incident.summary ??
    "No incident summary available.";

  const telemetry =
    incident.telemetry ?? {};

  const user =
    incident.affected_user ??
    "Not provided";

  const profile =
    telemetry.user_profiles?.[user] ??
    {};

  const authEvents =
    telemetry.authentication_history?.[user] ??
    [];

  const activityEvents =
    telemetry.user_activity?.[user] ??
    [];

  const lastAuth =
    authEvents.length > 0
      ? authEvents[authEvents.length - 1]
      : null;

  const host =
    incident.affected_host ??
    incident.hosts?.[0] ??
    "Not provided";

  const location =
    lastAuth?.geo ??
    profile.usual_locations?.[0] ??
    "Not provided";

  /*
   * Build useful evidence for the UI.
   */
  const evidence: {
    label: string;
    value: string;
  }[] = [
    {
      label: "Incident type",
      value: incidentType,
    },
    {
      label: "Source",
      value:
        incident.source ??
        "FastAPI backend",
    },
  ];

  if (user !== "Not provided") {
    evidence.push({
      label: "Affected user",
      value: user,
    });
  }

  if (host !== "Not provided") {
    evidence.push({
      label: "Affected host",
      value: host,
    });
  }

  if (profile.role) {
    evidence.push({
      label: "User role",
      value: profile.role,
    });
  }

  if (lastAuth) {
    evidence.push({
      label: "Authentication",
      value: `${lastAuth.geo ?? "Unknown"} · ${
        lastAuth.ip ?? "no IP"
      } · ${lastAuth.mfa ?? "MFA unknown"}`,
    });
  }

  for (
    const activity of activityEvents.slice(0, 3)
  ) {
    const activityText =
      `${activity.action ?? ""} ${
        activity.resource ?? ""
      }`.trim();

    if (activityText) {
      evidence.push({
        label: activity.action
          ? "Activity"
          : "Evidence",
        value: activityText,
      });
    }
  }

  /*
   * Indicators.
   */
  const indicators =
    (incident.indicators ?? []).map(
      (value) => ({
        type: indicatorType(value),

        value,

        reputation:
          telemetry.indicators?.[value]
            ?.reputation === "malicious"
            ? "malicious"
            : telemetry.indicators?.[value]
                  ?.reputation ===
                "suspicious"
              ? "suspicious"
              : "unknown",
      }),
    );

  /*
   * Timeline.
   */
  const timeline = [
    ...authEvents.map((event) => ({
      time: event.time ?? "",

      text: `Authentication from ${
        event.geo ?? "unknown location"
      } (${event.ip ?? "no IP"})`,
    })),

    ...activityEvents.map((event) => ({
      time: event.time ?? "",

      text: `${event.action ?? "Activity"} — ${
        event.resource ?? ""
      }`.trim(),
    })),
  ]
    .filter((item) => item.time)
    .sort(
      (a, b) =>
        new Date(a.time).getTime() -
        new Date(b.time).getTime(),
    )
    .slice(-8);

  if (incident.reported_at) {
    timeline.push({
      time: incident.reported_at,
      text:
        "Incident reported / detection raised",
    });
  }

  return {
    id: incidentId,

    title: incidentType
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) =>
        letter.toUpperCase(),
      ),

    severity: "high",

    status: "detected",

    category:
      incidentTypeToCategory(
        incidentType,
      ),

    tags: [
      incidentTypeToCategory(
        incidentType,
      ),
    ],

    detectedAt:
      incident.reported_at ??
      incidentId,

    detectedAgo:
      "from backend",

    summary,

    assignee:
      "Unassigned",

    subject: {
      user,
      role:
        profile.role ??
        "Not provided",

      host,

      location,
    },

    evidence,

    indicators,

    timeline,

    playbookId:
      incidentTypeToPlaybook(
        incidentType,
      ),

    relatedExperienceIds: [],
  };
}

async function getJson<T>(
  path: string,
): Promise<T> {
  const response = await fetch(
    `${API_BASE_URL}${path}`,
  );

  if (!response.ok) {
    throw new Error(
      `Backend request failed: ${response.status} ${response.statusText}`,
    );
  }

  return response.json();
}

async function getBackendIncidentList(): Promise<
  BackendIncident[]
> {
  const response =
    await getJson<BackendIncidentListResponse>(
      "/incidents",
    );

  if (Array.isArray(response)) {
    return response;
  }

  return response.value ?? [];
}

export const api = {
  /*
   * ----------------------------------------------------
   * INCIDENTS
   * ----------------------------------------------------
   */

  listIncidents: async () => {
    const incidents =
      await getBackendIncidentList();

    return incidents.map(
      backendIncidentToFrontend,
    );
  },

  listActiveIncidents: async () => {
    const incidents =
      await api.listIncidents();

    return incidents.filter((incident) =>
      ACTIVE.includes(
        incident.status,
      ),
    );
  },

  listIncidentHistory: async () => {
    const incidents =
      await api.listIncidents();

    return incidents.filter(
      (incident) =>
        incident.status ===
        "resolved",
    );
  },

  getIncident: async (
    id: string,
  ) => {
    const incidents =
      await getBackendIncidentList();

    const backendIncident =
      incidents.find(
        (incident) =>
          (incident.incident_id ??
            incident.id) === id,
      );

    if (!backendIncident) {
      throw new Error(
        `Incident ${id} was not found in the backend.`,
      );
    }

    return backendIncidentToFrontend(
      backendIncident,
    );
  },

  /*
   * ----------------------------------------------------
   * INCIDENT ANALYSIS
   *
   * false = BEFORE HINDSIGHT
   * true  = AFTER HINDSIGHT
   *
   * The backend resolves the canonical incident
   * using incident_id.
   * ----------------------------------------------------
   */

  analyzeIncident: async (
    incidentId: string,
    useHindsight = false,
  ) => {
    const response = await fetch(
      `${API_BASE_URL}/incidents/analyze`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",
        },

        body: JSON.stringify({
          incident_id:
            incidentId,

          use_hindsight: 
            useHindsight,
        }),
      },
    );

    if (!response.ok) {
      const errorText =
        await response.text();

      throw new Error(
        `Incident analysis failed: ${response.status} ${errorText}`,
      );
    }

    return response.json();
  },

  /*
   * ----------------------------------------------------
   * HINDSIGHT MEMORY
   * ----------------------------------------------------
   */

  seedMemory: async () => {
    const response = await fetch(
      `${API_BASE_URL}/memory/seed`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",
        },

        body: JSON.stringify({}),
      },
    );

    if (!response.ok) {
      const errorText =
        await response.text();

      throw new Error(
        `Memory seed failed: ${response.status} ${errorText}`,
      );
    }

    return response.json();
  },

  /*
   * ----------------------------------------------------
   * PLAYBOOKS
   * ----------------------------------------------------
   */

  getBackendPlaybook: async (
    incidentType: string,
  ): Promise<BackendPlaybook> => {
    return getJson<BackendPlaybook>(
      `/playbooks/${incidentType}`,
    );
  },

  listPlaybooks: async () =>
    playbooks,

  getPlaybook: async (
    id: string,
  ) =>
    playbooks.find(
      (playbook) =>
        playbook.id === id,
    ) ?? null,

  /*
   * ----------------------------------------------------
   * EXPERIENCE
   * ----------------------------------------------------
   */

  listExperience: async () =>
    experienceRecords,

  getExperienceByIds: async (
    ids: string[],
  ) =>
    experienceRecords.filter(
      (record) =>
        ids.includes(record.id),
    ),

  /*
   * ----------------------------------------------------
   * ACTIONS
   * ----------------------------------------------------
   */

  listActions: async () =>
    responseActions,

  listAuditEvents: async () =>
    auditEvents,

  /*
   * ----------------------------------------------------
   * PROPOSALS
   * ----------------------------------------------------
   */

  listProposals: async () =>
    playbookProposals,

  getProposal: async (
    id: string,
  ) =>
    playbookProposals.find(
      (proposal) =>
        proposal.id === id,
    ) ?? null,

  /*
   * ----------------------------------------------------
   * APPROVE ACTION
   * ----------------------------------------------------
   */

  approveAction: async (
    incidentId: string,
    actionId: string,
  ) => {
    const response = await fetch(
      `${API_BASE_URL}/incidents/${incidentId}/approve-action`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",
        },

        body: JSON.stringify({
          action_id: actionId,

          decision: "approve",

          analyst_comment: "",

          lessons_learned: [],
        }),
      },
    );

    if (!response.ok) {
      const errorText =
        await response.text();

      throw new Error(
        `Action approval failed: ${response.status} ${errorText}`,
      );
    }

    return response.json();
  },

  /*
   * ----------------------------------------------------
   * POSTPONE / REJECT ACTION
   * ----------------------------------------------------
   */

  postponeAction: async (
    incidentId: string,
    actionId: string,
  ) => {
    const response = await fetch(
      `${API_BASE_URL}/incidents/${incidentId}/approve-action`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",
        },

        body: JSON.stringify({
          action_id: actionId,

          decision: "reject",

          analyst_comment: "",

          lessons_learned: [],
        }),
      },
    );

    if (!response.ok) {
      const errorText =
        await response.text();

      throw new Error(
        `Action rejection failed: ${response.status} ${errorText}`,
      );
    }

    return response.json();
  },

  /*
   * ----------------------------------------------------
   * PLAYBOOK PROPOSAL DECISION
   * ----------------------------------------------------
   */

  decideProposal: async (
    proposalId: string,
    decision:
      | "approved"
      | "rejected",
  ) => ({
    proposalId,
    decision,
  }),
};

export type Api = typeof api;

export type {
  AuditEvent,
  ExperienceRecord,
  Incident,
  Playbook,
  PlaybookProposal,
  ResponseAction,
};