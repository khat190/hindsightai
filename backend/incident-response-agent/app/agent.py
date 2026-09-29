from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from .config import Settings
from .errors import AppError, ConflictError, NotFoundError, ValidationFailed
from .hindsight_client import MemoryHit, MemoryService, incident_to_memory_text
from .incidents import IncidentStore, incident_entities, validate_incident
from .llm import LLMClient
from .playbooks import PlaybookLibrary
from .tools import CONSEQUENTIAL, CONTAINMENT, MockSecurityTools


SEVERITIES = ("P1", "P2", "P3", "P4")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AgentController:
    def __init__(self) -> None:
        self.settings = Settings.from_env()
        self.memory = MemoryService(self.settings)
        self.llm = LLMClient(self.settings)
        self.playbooks = PlaybookLibrary(self.settings.playbook_dir)
        self.incidents = IncidentStore(self.settings.incident_dir)
        self.sessions: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict:
        memory_status = self.memory.status()

        return {
            "status": "ok",
            "llm": {
                "mode": self.settings.llm_mode,
                "configured": (
                    True
                    if self.settings.llm_mode == "mock"
                    else bool(self.settings.llm_api_key)
                ),
            },
            "memory": memory_status,
            "playbooks": len(self.playbooks.list()),
            "current_incidents": len(self.incidents.current()),
            "historical_incidents": len(self.incidents.historical()),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _incident_context(incident: dict) -> dict:
        hosts = list(incident.get("hosts") or [])

        affected_host = incident.get("affected_host")

        if affected_host and affected_host not in hosts:
            hosts.insert(0, affected_host)

        if not affected_host and hosts:
            affected_host = hosts[0]

        return {
            "incident_id": incident.get("incident_id"),
            "incident_type": incident.get("incident_type"),
            "summary": incident.get("summary"),
            "affected_user": incident.get("affected_user"),
            "affected_host": affected_host,
            "hosts": hosts,
            "indicators": list(incident.get("indicators") or []),
            "source": incident.get("source"),
            "reported_at": incident.get("reported_at"),
            "telemetry": deepcopy(incident.get("telemetry") or {}),
        }

    def _load_incident(
        self,
        incident_id: str | None,
        incident: dict | None,
    ) -> dict:
        if incident is not None:
            validate_incident(incident)
            return deepcopy(incident)

        if incident_id:
            return deepcopy(self.incidents.get_current(incident_id))

        raise ValidationFailed("incident_id or incident is required")

    def _get_session(self, incident_id: str) -> dict:
        session = self.sessions.get(incident_id)

        if session is None:
            raise NotFoundError(
                f"No active session for incident {incident_id}"
            )

        return session

    # ------------------------------------------------------------------
    # Investigation
    # ------------------------------------------------------------------

    def _investigate(self, incident: dict) -> list[dict]:
        telemetry = deepcopy(incident.get("telemetry") or {})

        tools = MockSecurityTools(telemetry)
        results: list[dict] = []

        affected_user = incident.get("affected_user")

        if affected_user:
            results.append(
                tools.get_authentication_history(affected_user)
            )
            results.append(
                tools.get_user_activity(affected_user)
            )
            results.append(
                tools.search_logs(affected_user)
            )

        indicators = list(incident.get("indicators") or [])

        telemetry_indicators = telemetry.get("indicators") or {}

        if isinstance(telemetry_indicators, dict):
            for indicator in telemetry_indicators:
                if indicator not in indicators:
                    indicators.append(indicator)

        for indicator in indicators:
            results.append(
                tools.check_indicator(indicator)
            )

        hosts = list(incident.get("hosts") or [])

        affected_host = incident.get("affected_host")

        if affected_host and affected_host not in hosts:
            hosts.insert(0, affected_host)

        for host in hosts:
            results.append(
                tools.get_endpoint_activity(host)
            )

        if telemetry.get("logs"):
            results.append(
                tools.search_logs(
                    incident.get("incident_type") or "incident"
                )
            )

        return results

    @staticmethod
    def _build_tool_context(
        investigation: list[dict],
    ) -> dict:
        """
        Convert the raw investigation list into the exact structure
        expected by the deterministic mock reasoner in llm.py.
        """
        context = {
            "auth": {},
            "activity": {},
            "indicators": {},
            "logs": {
                "results": [],
            },
            "endpoint_activity": {},
        }

        for result in investigation:
            if not isinstance(result, dict):
                continue

            tool = result.get("tool")

            if tool == "get_authentication_history":
                if not context["auth"]:
                    context["auth"] = deepcopy(result)

            elif tool == "get_user_activity":
                if not context["activity"]:
                    context["activity"] = deepcopy(result)

            elif tool == "check_indicator":
                target = result.get("target")

                if target:
                    context["indicators"][str(target)] = deepcopy(result)

            elif tool == "search_logs":
                results = result.get("results") or []

                if isinstance(results, list):
                    context["logs"]["results"].extend(
                        deepcopy(results)
                    )

            elif tool == "get_endpoint_activity":
                target = result.get("target")

                if target:
                    context["endpoint_activity"][str(target)] = deepcopy(
                        result
                    )

        return context

    @staticmethod
    def _build_memory_context(
        memories: list[dict | MemoryHit],
    ) -> list[dict]:
        """
        Normalize Hindsight records into the structure expected by
        the mock reasoner while preserving the original records
        separately for the API response.
        """
        normalized: list[dict] = []

        for index, memory in enumerate(memories):
            if isinstance(memory, MemoryHit):
                memory = memory.to_dict()

            if not isinstance(memory, dict):
                continue

            text = (
                memory.get("text")
                or memory.get("content")
                or memory.get("memory")
                or ""
            )

            ref = (
                memory.get("ref")
                or memory.get("memory_id")
                or memory.get("id")
                or f"memory-{index + 1}"
            )

            normalized.append(
                {
                    **deepcopy(memory),
                    "ref": str(ref),
                    "text": str(text),
                }
            )

        return normalized

    # ------------------------------------------------------------------
    # Hindsight query construction
    # ------------------------------------------------------------------

    def _recall_query(
        self,
        incident: dict,
        investigation: list[dict],
    ) -> str:
        auth_events: list[dict] = []
        activity_events: list[dict] = []
        privileged = False

        for result in investigation:
            if not isinstance(result, dict):
                continue

            result_type = (
                result.get("tool")
                or result.get("type")
            )

            if result_type in {
                "get_authentication_history",
                "auth_history",
                "get_auth_history",
            }:
                auth_events.append(result)

            if result_type in {
                "get_user_activity",
                "user_activity",
            }:
                activity_events.append(result)

            profile = result.get("profile")

            if isinstance(profile, dict):
                privileged = privileged or bool(
                    profile.get("privileged")
                    or profile.get("is_privileged")
                )

        flags: list[str] = []

        for result in auth_events:
            text = str(result).lower()

            if "failed" in text:
                flags.append(
                    "failed authentication activity"
                )

            if "success" in text:
                flags.append(
                    "successful authentication activity"
                )

            if "impossible" in text:
                flags.append(
                    "impossible-travel style authentication"
                )

            if "mfa" in text:
                flags.append(
                    "MFA-related activity"
                )

        actions: list[str] = []

        for result in activity_events:
            events = result.get("events")

            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict):
                        action = event.get("action")

                        if action:
                            actions.append(str(action))

        incident_type = (
            incident.get("incident_type")
            or "security incident"
        )

        user = (
            incident.get("affected_user")
            or "unknown user"
        )

        host = (
            incident.get("affected_host")
            or (incident.get("hosts") or [None])[0]
            or "unknown host"
        )

        context_parts = [
            f"incident type: {incident_type}",
            f"user: {user}",
            f"host: {host}",
        ]

        if flags:
            context_parts.append(
                "observed signals: "
                + ", ".join(sorted(set(flags)))
            )

        if actions:
            context_parts.append(
                "observed activity: "
                + ", ".join(sorted(set(actions))[:10])
            )

        if privileged:
            context_parts.append(
                "user appears privileged"
            )

        context = "; ".join(context_parts)

        return (
            "Previous security incidents similar to "
            "the following incident. What actions were "
            "taken, what worked or failed, and what "
            "lessons were learned? "
            f"{context}"
        )

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(
        self,
        incident_id: str | None = None,
        incident: dict | None = None,
        use_hindsight: bool | None = None,
    ) -> dict:
        inc = self._load_incident(
            incident_id,
            incident,
        )

        resolved_id = inc.get("incident_id")

        if not resolved_id:
            raise ValidationFailed(
                "Incident is missing incident_id"
            )

        playbook = self.playbooks.get(
            inc.get("incident_type")
        )

        if playbook is None:
            raise NotFoundError(
                f"No playbook found for incident type "
                f"{inc.get('incident_type')}"
            )

        if use_hindsight is None:
            use_hindsight = (
                self.settings.memory_backend != "disabled"
            )

        session = self.sessions.setdefault(
            resolved_id,
            {
                "incident": deepcopy(inc),
                "runs": [],
                "actions": {},
                "audit": [],
                "simulated_state": {},
            },
        )

        session["incident"] = deepcopy(inc)

        investigation = self._investigate(inc)

        memories: list[dict] = []

        if use_hindsight:
            query = self._recall_query(
                inc,
                investigation,
            )

            try:
                recalled = self.memory.recall(
                    query=query,
                    max_results=5,
                )

                if isinstance(recalled, list):
                    memories = recalled
                elif isinstance(recalled, dict):
                    candidate = (
                        recalled.get("memories")
                        or recalled.get("results")
                        or []
                    )

                    if isinstance(candidate, list):
                        memories = candidate

            except Exception:
                memories = []

        llm_memories = self._build_memory_context(
            memories
        )

        llm_tool_results = self._build_tool_context(
            investigation
        )

        llm_context = {
            "incident": self._incident_context(inc),
            "tool_results": llm_tool_results,
            "playbook": playbook,
            "memories": llm_memories,
        }

        # IMPORTANT:
        # LLMClient exposes complete_json(), not analyze().
        llm_result = self.llm.complete_json(
            llm_context
        )

        if not isinstance(llm_result, dict):
            llm_result = {}

        normalized = self._normalize(
            incident=inc,
            playbook=playbook,
            investigation=investigation,
            memories=memories,
            use_hindsight=bool(use_hindsight),
            llm_result=llm_result,
        )

        run = {
            "run_id": (
                f"{resolved_id}-"
                f"{len(session['runs']) + 1}"
            ),
            "created_at": _now(),
            "use_hindsight": bool(use_hindsight),
            "analysis": normalized,
        }

        session["runs"].append(run)

        for action in normalized.get(
            "recommended_actions",
            [],
        ):
            action_id = action.get("action_id")

            if action_id:
                session["actions"][action_id] = {
                    **deepcopy(action),
                    "status": "pending",
                }

        session["audit"].append(
            {
                "timestamp": _now(),
                "event": "analysis_completed",
                "incident_id": resolved_id,
                "use_hindsight": bool(use_hindsight),
                "memory_count": len(memories),
            }
        )

        normalized["run_id"] = run["run_id"]

        return normalized

    # ------------------------------------------------------------------
    # Normalize LLM result
    # ------------------------------------------------------------------

    def _normalize(
        self,
        incident: dict,
        playbook: dict,
        investigation: list[dict],
        memories: list[dict],
        use_hindsight: bool,
        llm_result: dict | None,
    ) -> dict:
        result = llm_result or {}

        severity = (
            result.get("severity")
            or incident.get("severity")
            or "P2"
        )

        if severity not in SEVERITIES:
            severity = "P2"

        try:
            confidence = float(
                result.get(
                    "confidence",
                    0.85,
                )
            )
        except (TypeError, ValueError):
            confidence = 0.85

        confidence = max(
            0.0,
            min(1.0, confidence),
        )

        entities = incident_entities(incident)

        entity_values = {
            str(entity)
            for entity in entities
        }

        raw_actions = (
            result.get("recommended_actions")
            or []
        )

        if not isinstance(raw_actions, list):
            raw_actions = []

        recommended_actions: list[dict] = []

        for index, raw_action in enumerate(raw_actions):
            if not isinstance(raw_action, dict):
                continue

            action = deepcopy(raw_action)

            source_order = action.get(
                "order",
                index + 1,
            )

            action_id = (
                action.get("action_id")
                or action.get("id")
                or f"action-{index + 1}"
            )

            action_id = str(action_id)

            existing_ids = {
                existing.get("action_id")
                for existing in recommended_actions
            }

            if action_id in existing_ids:
                action_id = f"{action_id}-{index + 1}"

            action["action_id"] = action_id

            action["_source_order"] = source_order

            action_type = (
                action.get("action_type")
                or action.get("tool")
                or action.get("type")
                or action.get("action")
                or "investigate"
            )

            action["action_type"] = str(action_type)

            target = action.get("target")

            # create_ticket intentionally uses a summary as its target.
            if (
                action["action_type"] != "create_ticket"
                and target is not None
                and entity_values
                and str(target) not in entity_values
            ):
                action["target"] = None
                action["target_validation"] = "unresolved"
            else:
                action.setdefault(
                    "target_validation",
                    "resolved",
                )

            if action["action_type"] in CONSEQUENTIAL:
                action["requires_human_approval"] = True
            else:
                action.setdefault(
                    "requires_human_approval",
                    False,
                )

            recommended_actions.append(action)

        # Map the LLM's numeric dependency references BEFORE any
        # display-order changes are made.
        source_order_to_id: dict[object, str] = {}

        for action in recommended_actions:
            source_order = action.get("_source_order")

            if source_order is not None:
                source_order_to_id[source_order] = action["action_id"]

                try:
                    source_order_to_id[int(source_order)] = action[
                        "action_id"
                    ]
                except (TypeError, ValueError):
                    pass

        for action in recommended_actions:
            dependencies = action.get("depends_on") or []

            if not isinstance(dependencies, list):
                dependencies = [dependencies]

            normalized_dependencies: list[str] = []

            for dependency in dependencies:
                mapped = source_order_to_id.get(dependency)

                if mapped is None:
                    try:
                        mapped = source_order_to_id.get(
                            int(dependency)
                        )
                    except (TypeError, ValueError):
                        mapped = None

                if mapped is not None:
                    normalized_dependencies.append(mapped)
                    continue

                dependency_text = str(dependency)

                if dependency_text in {
                    candidate.get("action_id")
                    for candidate in recommended_actions
                }:
                    normalized_dependencies.append(
                        dependency_text
                    )

            action["depends_on"] = normalized_dependencies

        # Preserve evidence before containment.
        preserve_actions = [
            action
            for action in recommended_actions
            if str(
                action.get("action_type", "")
            ).lower()
            in {
                "preserve_evidence",
                "collect_evidence",
                "snapshot",
            }
        ]

        containment_actions = [
            action
            for action in recommended_actions
            if str(
                action.get("action_type", "")
            ).lower()
            in CONTAINMENT
        ]

        if preserve_actions and containment_actions:
            ordered: list[dict] = []

            preserve_ids = {
                action["action_id"]
                for action in preserve_actions
            }

            containment_ids = {
                action["action_id"]
                for action in containment_actions
            }

            for action in recommended_actions:
                if action["action_id"] in preserve_ids:
                    ordered.append(action)

            for action in recommended_actions:
                if (
                    action["action_id"] not in preserve_ids
                    and action["action_id"] not in containment_ids
                ):
                    ordered.append(action)

            for action in recommended_actions:
                if action["action_id"] in containment_ids:
                    ordered.append(action)

            recommended_actions = ordered

        # Final display order.
        for index, action in enumerate(recommended_actions):
            action["order"] = index + 1
            action.pop("_source_order", None)

        historical_context: list[dict] = []

        if use_hindsight:
            for memory in memories:
                if not isinstance(memory, dict):
                    continue

                historical_context.append(
                    {
                        "memory_id": (
                            memory.get("memory_id")
                            or memory.get("id")
                            or memory.get("ref")
                        ),
                        "text": (
                            memory.get("text")
                            or memory.get("content")
                            or memory.get("memory")
                        ),
                        "score": memory.get("score"),
                        "metadata": (
                            memory.get("metadata")
                            or {}
                        ),
                    }
                )

        if not historical_context and use_hindsight:
            historical_context = [
                {
                    "memory_id": None,
                    "text": (
                        "No matching historical "
                        "incident was retrieved "
                        "from Hindsight."
                    ),
                    "score": None,
                    "metadata": {},
                }
            ]

        historical_note = None

        if use_hindsight:
            if memories:
                historical_note = (
                    f"{len(memories)} historical "
                    "memory record(s) were recalled "
                    "and considered."
                )
            else:
                historical_note = (
                    "Hindsight was enabled, but no "
                    "historical memories were recalled."
                )

        reasoning_summary = (
            result.get("reasoning_summary")
            or result.get("reasoning")
            or (
                "The incident was investigated using "
                "the available security telemetry and "
                "the configured playbook."
            )
        )

        next_step = (
            result.get("next_step")
            or (
                "Review the recommended actions and "
                "approve any consequential containment "
                "steps."
            )
        )

        warnings = result.get("warnings") or []

        if not isinstance(warnings, list):
            warnings = [str(warnings)]

        policy_conflicts = (
            result.get("policy_conflicts")
            or []
        )

        if not isinstance(policy_conflicts, list):
            policy_conflicts = [str(policy_conflicts)]

        requires_human_approval = any(
            bool(
                action.get(
                    "requires_human_approval"
                )
            )
            for action in recommended_actions
        )

        return {
            "incident_id": incident.get("incident_id"),
            "incident_context": self._incident_context(
                incident
            ),
            "mode": {
                "use_hindsight": use_hindsight,
                "llm": self.settings.llm_mode,
                "memory_backend": self.settings.memory_backend,
            },
            "assessment": (
                result.get("assessment")
                or incident.get("summary")
                or (
                    "Security incident requiring "
                    "investigation."
                )
            ),
            "severity": severity,
            "confidence": confidence,
            "playbook": playbook,
            "evidence_considered": investigation,
            "investigation_tools_run": [
                item.get("tool")
                for item in investigation
                if (
                    isinstance(item, dict)
                    and item.get("tool")
                )
            ],
            "retrieved_memories": (
                memories
                if use_hindsight
                else []
            ),
            "historical_context": historical_context,
            "historical_note": historical_note,
            "recommended_actions": recommended_actions,
            "policy_conflicts": policy_conflicts,
            "requires_human_approval": (
                requires_human_approval
            ),
            "reasoning_summary": reasoning_summary,
            "next_step": next_step,
            "warnings": warnings,
        }

    # ------------------------------------------------------------------
    # Approve / execute action
    # ------------------------------------------------------------------

    def approve_action(
        self,
        incident_id: str,
        action_id: str,
        approved: bool = True,
        rationale: str | None = None,
    ) -> dict:
        session = self._get_session(incident_id)

        action = session["actions"].get(action_id)

        if action is None:
            raise NotFoundError(
                f"Action {action_id} was not found "
                f"for incident {incident_id}"
            )

        if action.get("status") == "executed":
            raise ConflictError(
                f"Action {action_id} has already been executed"
            )

        if action.get("status") == "rejected":
            raise ConflictError(
                f"Action {action_id} has already been rejected"
            )

        dependencies = action.get("depends_on") or []

        if not isinstance(dependencies, list):
            dependencies = [dependencies]

        for dependency_id in dependencies:
            dependency = session["actions"].get(
                dependency_id
            )

            if dependency is None:
                raise ConflictError(
                    f"Dependency {dependency_id} is missing"
                )

            if dependency.get("status") != "executed":
                raise ConflictError(
                    f"Action {action_id} depends on "
                    f"{dependency_id}, which has not been executed"
                )

        action["rationale"] = rationale
        action["decision_at"] = _now()

        if not approved:
            action["status"] = "rejected"

            session["audit"].append(
                {
                    "timestamp": _now(),
                    "event": "action_rejected",
                    "incident_id": incident_id,
                    "action_id": action_id,
                    "rationale": rationale,
                }
            )

            self._retain_experience(
                incident_id=incident_id,
                session=session,
            )

            return {
                "incident_id": incident_id,
                "action_id": action_id,
                "status": "rejected",
                "executed": False,
                "outcome": {
                    "success": False,
                    "message": (
                        "Action rejected by human approval."
                    ),
                },
                "unlocked_actions": [],
            }

        incident = session.get("incident") or {}

        tools = MockSecurityTools(
            deepcopy(
                incident.get("telemetry") or {}
            )
        )

        action_type = (
            action.get("action_type")
            or action.get("tool")
            or action.get("type")
            or action.get("action")
        )

        target = action.get("target")

        if not action_type:
            raise ValidationFailed(
                f"Action {action_id} does not specify an action type"
            )

        if not target:
            raise ValidationFailed(
                f"Action {action_id} does not have a valid target"
            )

        if action_type not in CONSEQUENTIAL:
            outcome = {
                "success": True,
                "simulated": True,
                "tool": action_type,
                "target": target,
                "message": (
                    "Non-consequential action completed "
                    "without requiring containment execution."
                ),
                "timestamp": _now(),
            }
        else:
            try:
                raw_outcome = tools.execute(
                    action_type,
                    str(target),
                )

                success = (
                    raw_outcome.get("status")
                    == "simulated_success"
                )

                outcome = {
                    **raw_outcome,
                    "success": success,
                }

            except Exception as exc:
                outcome = {
                    "success": False,
                    "simulated": True,
                    "tool": action_type,
                    "target": target,
                    "message": str(exc),
                    "timestamp": _now(),
                }

        action["status"] = (
            "executed"
            if outcome.get("success")
            else "failed"
        )

        action["executed_at"] = _now()
        action["outcome"] = outcome

        session["audit"].append(
            {
                "timestamp": _now(),
                "event": (
                    "action_executed"
                    if outcome.get("success")
                    else "action_failed"
                ),
                "incident_id": incident_id,
                "action_id": action_id,
                "outcome": outcome,
            }
        )

        self._retain_experience(
            incident_id=incident_id,
            session=session,
        )

        unlocked_actions: list[dict] = []

        for candidate in session["actions"].values():
            if candidate.get("status") != "pending":
                continue

            candidate_dependencies = (
                candidate.get("depends_on") or []
            )

            if not isinstance(candidate_dependencies, list):
                candidate_dependencies = [
                    candidate_dependencies
                ]

            if all(
                session["actions"].get(
                    dep_id,
                    {},
                ).get("status") == "executed"
                for dep_id in candidate_dependencies
            ):
                unlocked_actions.append(
                    deepcopy(candidate)
                )

        return {
            "incident_id": incident_id,
            "action_id": action_id,
            "status": action["status"],
            "executed": (
                action["status"] == "executed"
            ),
            "outcome": outcome,
            "unlocked_actions": unlocked_actions,
        }

    # ------------------------------------------------------------------
    # Retain experience
    # ------------------------------------------------------------------

    def _retain_experience(
        self,
        incident_id: str,
        session: dict,
    ) -> None:
        incident = session.get("incident") or {}

        executed_actions = []

        for action in session.get("actions", {}).values():
            if action.get("status") == "executed":
                executed_actions.append(
                    {
                        "action_id": action.get("action_id"),
                        "action_type": action.get("action_type"),
                        "target": action.get("target"),
                        "outcome": action.get("outcome"),
                    }
                )

        memory_text = incident_to_memory_text(
            {
                **incident,
                "incident_id": incident_id,
                "actions": executed_actions,
            }
        )

        if not memory_text:
            return

        try:
            self.memory.retain(
                text=memory_text,
                metadata={
                    "incident_id": incident_id,
                    "incident_type": incident.get(
                        "incident_type"
                    ),
                    "severity": incident.get("severity"),
                    "source": "incident-response-agent",
                },
            )
        except Exception:
            return

    # ------------------------------------------------------------------
    # Incident state
    # ------------------------------------------------------------------

    def get_incident_state(
        self,
        incident_id: str,
    ) -> dict:
        session = self._get_session(incident_id)

        return {
            "incident_id": incident_id,
            "incident": deepcopy(
                session.get("incident") or {}
            ),
            "latest_analysis": (
                deepcopy(
                    session["runs"][-1]["analysis"]
                )
                if session.get("runs")
                else None
            ),
            "actions": deepcopy(
                list(
                    session.get(
                        "actions",
                        {},
                    ).values()
                )
            ),
            "audit": deepcopy(
                session.get("audit", [])
            ),
            "simulated_state": deepcopy(
                session.get("simulated_state", {})
            ),
        }

    # ------------------------------------------------------------------
    # Current incidents
    # ------------------------------------------------------------------

    def list_current(self) -> list[dict]:
        """
        Return the complete canonical incident records.
        """
        return [
            deepcopy(incident)
            for incident in self.incidents.current().values()
        ]

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def get_playbook(
        self,
        incident_type: str,
    ) -> dict:
        playbook = self.playbooks.get(incident_type)

        if playbook is None:
            raise NotFoundError(
                f"No playbook found for incident type "
                f"{incident_type}"
            )

        return playbook

    # ------------------------------------------------------------------
    # Hindsight recall
    # ------------------------------------------------------------------

    def recall(
        self,
        query: str,
        limit: int = 5,
    ) -> dict:
        try:
            memories = self.memory.recall(
                query=query,
                limit=limit,
            )

            if not isinstance(memories, list):
                if isinstance(memories, dict):
                    memories = (
                        memories.get("memories")
                        or memories.get("results")
                        or []
                    )
                else:
                    memories = []

        except Exception as exc:
            raise AppError(
                f"Hindsight recall failed: {exc}"
            ) from exc

        return {
            "query": query,
            "memories": memories,
            "count": len(memories),
        }

    # ------------------------------------------------------------------
    # Manual memory retention
    # ------------------------------------------------------------------

    def retain(
        self,
        text: str,
        metadata: dict | None = None,
    ) -> dict:
        if not text or not text.strip():
            raise ValidationFailed("text is required")

        try:
            return self.memory.retain(
                text=text,
                metadata=metadata or {},
            )
        except Exception as exc:
            raise AppError(
                f"Hindsight retention failed: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Seed historical memories
    # ------------------------------------------------------------------

    def seed(
        self,
        incident_ids: list[str] | None = None,
    ) -> dict:
        historical = self.incidents.historical()

        if incident_ids:
            requested_ids = set(incident_ids)

            historical = {
                incident_id: incident
                for incident_id, incident in historical.items()
                if incident_id in requested_ids
            }

        seeded = 0
        skipped = 0

        for incident in historical.values():
            try:
                text = incident_to_memory_text(incident)

                if not text:
                    skipped += 1
                    continue

                self.memory.retain(
                    text=text,
                    metadata={
                        "incident_id": incident.get(
                            "incident_id"
                        ),
                        "incident_type": incident.get(
                            "incident_type"
                        ),
                        "severity": incident.get(
                            "severity"
                        ),
                        "source": "historical-seed",
                    },
                )

                seeded += 1

            except Exception:
                skipped += 1

        return {
            "seeded": seeded,
            "skipped": skipped,
            "total_historical": len(historical),
        }