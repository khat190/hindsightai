import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  answerAnalyst,
  getAgentScript,
} from "@/data/agent-scripts";

import { api } from "@/services/api";

import type {
  FeedItem,
  Incident,
  IncidentStatus,
} from "@/types/incident";

let seq = 0;

const nextId = () =>
  `f${++seq}`;

export function useIncidentSession(
  incident: Incident,
) {
  const [feed, setFeed] =
    useState<FeedItem[]>([]);

  const [status, setStatus] =
    useState<IncidentStatus>(
      incident.status,
    );

  const [agentBusy, setAgentBusy] =
    useState(true);

  const [backendAnalysis, setBackendAnalysis] =
    useState<any>(null);

  const [baselineAnalysis, setBaselineAnalysis] =
    useState<any>(null);

  const timers =
    useRef<
      ReturnType<typeof setTimeout>[]
    >([]);

  const script =
    useRef(
      getAgentScript(incident),
    );

  const later = useCallback(
    (
      ms: number,
      fn: () => void,
    ) => {
      timers.current.push(
        setTimeout(fn, ms),
      );
    },
    [],
  );

  const patch = useCallback(
    (
      id: string,
      update: (
        item: FeedItem,
      ) => FeedItem,
    ) => {
      setFeed((prev) =>
        prev.map((item) =>
          item.id === id
            ? update(item)
            : item,
        ),
      );
    },
    [],
  );

  const push = useCallback(
    (item: FeedItem) => {
      setFeed((prev) => [
        ...prev,
        item,
      ]);
    },
    [],
  );

  const advance = useCallback(
    (
      blockId: string,
      count: number,
      startAt: number,
      per: number,
      onDone?: () => void,
    ) => {
      for (
        let idx = 0;
        idx < count;
        idx++
      ) {
        later(
          startAt + idx * per,
          () =>
            patch(
              blockId,
              (item) =>
                item.kind ===
                  "investigation" ||
                item.kind ===
                  "execution"
                  ? {
                      ...item,
                      steps:
                        item.steps.map(
                          (
                            step,
                            index,
                          ) =>
                            index <
                            idx
                              ? {
                                  ...step,
                                  state:
                                    "done",
                                }
                              : index ===
                                  idx
                                ? {
                                    ...step,
                                    state:
                                      "running",
                                  }
                                : step,
                        ),
                    }
                  : item,
            ),
        );
      }

      later(
        startAt +
          count * per,
        () => {
          patch(
            blockId,
            (item) =>
              item.kind ===
                "investigation" ||
              item.kind ===
                "execution"
                ? {
                    ...item,
                    steps:
                      item.steps.map(
                        (step) => ({
                          ...step,
                          state:
                            "done" as const,
                        }),
                      ),
                  }
                : item,
          );

          onDone?.();
        },
      );
    },
    [later, patch],
  );

  const presentPlan =
    useCallback(() => {
      const s =
        script.current;

      const backendAction =
        backendAnalysis
          ?.recommended_actions?.[0];

      const tool =
        backendAction?.tool ??
        s.planAction.tool;

      const target =
        backendAction?.target ??
        s.planAction.target;

      const actionNames: Record<
        string,
        string
      > = {
        preserve_evidence:
          "Preserve evidence",
        revoke_sessions:
          "Revoke active sessions",
        disable_account:
          "Disable account",
        remove_unauthorized_access:
          "Remove unauthorized access",
        block_indicator:
          "Block indicator",
        isolate_endpoint:
          "Isolate endpoint",
        create_ticket:
          "Create incident ticket",
      };

      const why =
        backendAnalysis?.assessment
          ? [
              backendAnalysis.assessment,
              ...(backendAnalysis
                ?.policy_conflicts ??
                []),
            ]
          : s.planWhy;

      push({
        kind: "plan",
        id: nextId(),
        recommendation:
          backendAction?.reason ??
          s.planRecommendation,
        why,
        action: {
          name:
            actionNames[tool] ??
            s.planAction.name,
          tool: tool as any,
          target,
        },
        decision: "pending",
      });

      setStatus(
        "awaiting_approval",
      );

      setAgentBusy(false);
    }, [
      backendAnalysis,
      push,
    ]);

  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      try {
        /*
         * Seed the organization's historical
         * incident experience first.
         */
        try {
          await api.seedMemory();
        } catch (error) {
          console.error(
            "Memory seed failed:",
            error,
          );
        }

        /*
         * BEFORE HINDSIGHT
         *
         * Current incident + current
         * evidence + approved playbook.
         *
         * IMPORTANT:
         * Hindsight is OFF here.
         */
        const before =
          await api.analyzeIncident(
            incident.id,
            false,
          );

        if (cancelled) {
          return;
        }

        setBaselineAnalysis(
          before,
        );

        /*
         * AFTER HINDSIGHT
         *
         * Same incident, but now with
         * historical experience recalled.
         *
         * IMPORTANT:
         * Hindsight is ON here.
         */
        const after =
          await api.analyzeIncident(
            incident.id,
            true,
          );

        if (cancelled) {
          return;
        }

        setBackendAnalysis(
          after,
        );
      } catch (error) {
        console.error(
          "Backend incident analysis failed:",
          error,
        );

        /*
         * Make sure the UI does not remain
         * stuck on "Agent working..." if
         * either analysis request fails.
         */
        setAgentBusy(false);
      }
    };

    run();

    return () => {
      cancelled = true;
    };
  }, [incident.id]);

  useEffect(() => {
    if (
      !baselineAnalysis ||
      !backendAnalysis
    ) {
      return;
    }

    const s =
      script.current;

    const introId =
      nextId();

    const invId =
      nextId();

    /*
     * Real backend-driven introduction.
     */
    later(300, () => {
      const evidence =
        backendAnalysis
          ?.evidence_considered ??
        [];

      const firstEvidence =
        Array.isArray(evidence) &&
        evidence.length > 0
          ? ` I found ${evidence.length} pieces of backend evidence, including authentication and post-login activity.`
          : "";

      push({
        kind: "agent",
        id: introId,
        text:
          `I've loaded ${incident.id} from the incident-response backend and investigated the current evidence.${firstEvidence}`,
      });
    });

    /*
     * Investigation block.
     */
    later(1000, () => {
      const toolNames =
        backendAnalysis
          ?.investigation_tools_run ??
        [];

      const labels =
        [
          "Authentication history checked",
          "User activity checked",
          "Indicator reputation checked",
          "Security logs checked",
        ].slice(
          0,
          Math.max(
            3,
            Array.isArray(toolNames)
              ? toolNames.length
              : 3,
          ),
        );

      push({
        kind: "investigation",
        id: invId,
        title:
          s.investigationTitle,
        steps:
          s.investigation.map(
            (step, index) => ({
              ...step,
              label:
                labels[index] ??
                step.label,
            }),
          ),
      });

      setStatus(
        "investigating",
      );
    });

    /*
     * Show the baseline result.
     */
    advance(
      invId,
      s.investigation.length,
      1500,
      650,
      () => {
        const beforeText =
          baselineAnalysis
            .reasoning_summary ??
          "The incident was analyzed using only the current incident evidence and approved playbook.";

        push({
          kind: "agent",
          id: nextId(),
          text:
            `BEFORE HINDSIGHT\n\n${beforeText}`,
        });

        later(700, () => {
          const memories =
            backendAnalysis
              ?.retrieved_memories ??
            [];

          const historical =
            backendAnalysis
              ?.historical_context ??
            [];

          const memoryLines =
            Array.isArray(
              historical,
            )
              ? historical
                  .map(
                    (memory: any) =>
                      `${memory.source_incident ?? memory.memory_ref}: ${memory.lesson ?? "Previous incident experience was recalled."}\nInfluence: ${memory.influence ?? "Reviewed as historical context."}`,
                  )
                  .join(
                    "\n\n",
                  )
              : "";

          const afterReasoning =
            backendAnalysis
              ?.reasoning_summary ??
            "The agent combined current evidence with recalled incident experience.";

          const memoryCount =
            Array.isArray(
              memories,
            )
              ? memories.length
              : 0;

          push({
            kind: "agent",
            id: nextId(),
            text:
              `AFTER HINDSIGHT\n\nI recalled ${memoryCount} relevant previous incident experiences and compared them with the current evidence and approved playbook.\n\n${memoryLines}\n\n${afterReasoning}`,
          });
        });

        later(
          1800,
          () => {
            presentPlan();
          },
        );
      },
    );

    return () => {
      timers.current.forEach(
        clearTimeout,
      );

      timers.current = [];
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    baselineAnalysis,
    backendAnalysis,
  ]);

  const sendMessage =
    useCallback(
      (text: string) => {
        push({
          kind: "analyst",
          id: nextId(),
          text,
        });

        setAgentBusy(true);

        later(850, () => {
          const answer =
            answerAnalyst(
              text,
              incident,
            );

          if (
            answer ===
            "__REPRESENT_PLAN__"
          ) {
            push({
              kind: "agent",
              id: nextId(),
              text:
                "Understood. Here is the pending action again for your authorization.",
            });

            later(
              400,
              () =>
                presentPlan(),
            );

            return;
          }

          push({
            kind: "agent",
            id: nextId(),
            text: answer,
          });

          setAgentBusy(false);
        });
      },
      [
        incident,
        later,
        presentPlan,
        push,
      ],
    );

  const approvePlan =
    useCallback(
      async (
        planId: string,
      ) => {
        const s =
          script.current;

        const actionId =
          backendAnalysis
            ?.recommended_actions?.[0]
            ?.action_id ??
          s.planAction.tool;

        patch(
          planId,
          (item) =>
            item.kind ===
            "plan"
              ? {
                  ...item,
                  decision:
                    "approved",
                }
              : item,
        );

        setStatus(
          "executing",
        );

        setAgentBusy(true);

        try {
          await api.approveAction(
            incident.id,
            actionId,
          );
        } catch (error) {
          console.error(
            "Backend action approval failed:",
            error,
          );

          setAgentBusy(false);
          return;
        }

        const execId =
          nextId();

        push({
          kind: "execution",
          id: execId,
          steps:
            s.execution,
        });

        advance(
          execId,
          s.execution.length,
          400,
          620,
          () => {
            push({
              kind: "completed",
              id: nextId(),
              summary:
                s.completedSummary,
              actions:
                s.completedActions,
            });

            setStatus(
              "resolved",
            );

            later(
              1300,
              () => {
                push({
                  kind: "proposal-offer",
                  id: nextId(),
                  text:
                    s.proposalOffer,
                  decision:
                    "pending",
                });

                setAgentBusy(
                  false,
                );
              },
            );
          },
        );
      },
      [
        advance,
        backendAnalysis,
        incident.id,
        later,
        patch,
        push,
      ],
    );

  const postponePlan =
    useCallback(
      async (
        planId: string,
      ) => {
        const actionId =
          backendAnalysis
            ?.recommended_actions?.[0]
            ?.action_id ??
          script.current
            .planAction.tool;

        patch(
          planId,
          (item) =>
            item.kind ===
            "plan"
              ? {
                  ...item,
                  decision:
                    "postponed",
                }
              : item,
        );

        try {
          await api.postponeAction(
            incident.id,
            actionId,
          );
        } catch (error) {
          console.error(
            "Backend action rejection failed:",
            error,
          );

          return;
        }

        push({
          kind: "agent",
          id: nextId(),
          text:
            "Nothing has been executed. The proposed action stays pending and the incident remains in a waiting state. Tell me to do it now when you're ready, or ask me to keep investigating.",
        });

        setStatus(
          "awaiting_approval",
        );
      },
      [
        backendAnalysis,
        incident.id,
        patch,
        push,
      ],
    );

  const openProposal =
    useCallback(
      (offerId: string) => {
        patch(
          offerId,
          (item) =>
            item.kind ===
            "proposal-offer"
              ? {
                  ...item,
                  decision:
                    "opened",
                }
              : item,
        );

        push({
          kind: "proposal",
          id: nextId(),
          proposalId:
            script.current
              .proposalId,
          status: "pending",
        });
      },
      [patch, push],
    );

  const declineProposal =
    useCallback(
      (offerId: string) => {
        patch(
          offerId,
          (item) =>
            item.kind ===
            "proposal-offer"
              ? {
                  ...item,
                  decision:
                    "declined",
                }
              : item,
        );

        push({
          kind: "agent",
          id: nextId(),
          text:
            "Understood — the playbook is unchanged. I've retained the observation with this incident's experience record so it can be reviewed later.",
        });
      },
      [patch, push],
    );

  const decideProposal =
    useCallback(
      async (
        itemId: string,
        decision:
          | "approved"
          | "rejected",
      ) => {
        await api.decideProposal(
          script.current
            .proposalId,
          decision,
        );

        patch(
          itemId,
          (item) =>
            item.kind ===
            "proposal"
              ? {
                  ...item,
                  status:
                    decision,
                }
              : item,
        );

        push({
          kind: "agent",
          id: nextId(),
          text:
            decision ===
            "approved"
              ? "The proposed revision is recorded against the playbook as a pending version for the playbook owner to publish. The organization's approved procedure is unchanged until they do."
              : "Proposal rejected. The approved playbook stays as it is, and I've noted your decision with the incident record.",
        });
      },
      [patch, push],
    );

  return {
    feed,
    status,
    agentBusy,
    sendMessage,
    approvePlan,
    postponePlan,
    openProposal,
    declineProposal,
    decideProposal,
  };
}