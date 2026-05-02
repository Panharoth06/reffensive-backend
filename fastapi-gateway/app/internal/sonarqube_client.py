import asyncio
import base64
import html
import time
from typing import Any

import httpx
from fastapi import HTTPException, status

RULE_DETAILS_CACHE_TTL_SECONDS = 300


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _derive_file_path(component_key: str) -> str:
    if ":" not in component_key:
        return component_key
    _, _, file_path = component_key.partition(":")
    return file_path or component_key


def _normalize_text_range(raw: Any, line: int | None) -> dict[str, int]:
    data = raw if isinstance(raw, dict) else {}
    start_line = _as_int(data.get("startLine")) or line or 0
    end_line = _as_int(data.get("endLine")) or start_line
    start_offset = _as_int(data.get("startOffset")) or 0
    end_offset = _as_int(data.get("endOffset")) or 0
    return {
        "startLine": start_line,
        "endLine": end_line,
        "startOffset": start_offset,
        "endOffset": end_offset,
    }


def _extract_code_snippet(payload: dict[str, Any]) -> str:
    sources = payload.get("sources")
    if isinstance(sources, list):
        rows: list[str] = []
        for item in sources:
            if isinstance(item, dict):
                code = item.get("code")
                if isinstance(code, str):
                    rows.append(code)
                    continue
            if isinstance(item, str):
                rows.append(item)
        return "\n".join(rows).strip()

    source = payload.get("source")
    if isinstance(source, str):
        return source.strip()

    lines = payload.get("lines")
    if isinstance(lines, list):
        rows = []
        for item in lines:
            if isinstance(item, dict):
                code = item.get("code")
                if isinstance(code, str):
                    rows.append(code)
                    continue
            if isinstance(item, str):
                rows.append(item)
        return "\n".join(rows).strip()

    return ""


def _normalize_description_sections(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []

    sections: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        key = _as_text(item.get("key") or item.get("name") or item.get("contextKey"))
        content = _as_text(item.get("content") or item.get("htmlContent") or item.get("context"))
        if not key or not content:
            continue
        sections.append({"key": key, "content": content})
    return sections


class SonarQubeClient:
    def __init__(self, host: str, token: str) -> None:
        clean_host = host.strip().rstrip("/")
        clean_token = token.strip()
        if not clean_host:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Missing SONARQUBE_BASE_URL",
            )
        if not clean_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Missing SONARQUBE_TOKEN",
            )
        self.host = clean_host
        self.token = clean_token
        self._rule_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._rule_cache_lock = asyncio.Lock()

    def _headers(self) -> dict[str, str]:
        basic = base64.b64encode(f"{self.token}:".encode("utf-8")).decode("utf-8")
        return {
            "Authorization": f"Basic {basic}",
            "Accept": "application/json",
        }

    def build_rule_documentation_url(self, rule_key: str) -> str | None:
        clean_key = rule_key.strip()
        if not clean_key:
            return None
        return f"{self.host}/coding_rules?open={clean_key}&rule_key={clean_key}"

    async def _request(
        self,
        *,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.host}{path}"
        timeout = httpx.Timeout(20.0, connect=10.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self._headers(),
                    params=params,
                    data=data,
                )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="SonarQube is unreachable",
            ) from exc

        try:
            payload = response.json()
        except ValueError:
            payload = {}

        if response.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid SonarQube token",
            )

        if response.status_code >= 400:
            detail = "SonarQube request failed"
            if isinstance(payload, dict):
                errors = payload.get("errors")
                if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                    message = _as_text(errors[0].get("msg"))
                    if message:
                        detail = message
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"SonarQube error ({response.status_code}): {detail}",
            )

        if not isinstance(payload, dict):
            return {}
        return payload

    async def health(self) -> dict[str, Any]:
        return await self._request(method="GET", path="/api/system/status")

    async def get_project(self, project_key: str) -> dict[str, Any] | None:
        payload = await self._request(
            method="GET",
            path="/api/projects/search",
            params={"projects": project_key},
        )
        components = payload.get("components")
        if not isinstance(components, list) or len(components) == 0:
            return None
        if not isinstance(components[0], dict):
            return None
        return components[0]

    async def create_project(
        self,
        *,
        project_key: str,
        project_name: str,
        main_branch: str | None,
        visibility: str | None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "project": project_key,
            "name": project_name,
        }
        if main_branch and main_branch.strip():
            data["mainBranch"] = main_branch.strip()
        if visibility and visibility.strip():
            data["visibility"] = visibility.strip()
        return await self._request(
            method="POST",
            path="/api/projects/create",
            data=data,
        )

    async def get_quality_gate(self, project_key: str) -> dict[str, Any]:
        payload = await self._request(
            method="GET",
            path="/api/qualitygates/project_status",
            params={"projectKey": project_key},
        )
        result = payload.get("projectStatus")
        if isinstance(result, dict):
            return result
        return {}

    async def get_ce_task(self, ce_task_id: str) -> dict[str, Any]:
        payload = await self._request(
            method="GET",
            path="/api/ce/task",
            params={"id": ce_task_id},
        )
        task = payload.get("task")
        if isinstance(task, dict):
            return task
        return {}

    async def get_measures(self, project_key: str, metric_keys: list[str]) -> dict[str, str]:
        payload = await self._request(
            method="GET",
            path="/api/measures/component",
            params={"component": project_key, "metricKeys": ",".join(metric_keys)},
        )
        component = payload.get("component")
        if not isinstance(component, dict):
            return {}
        measures = component.get("measures")
        if not isinstance(measures, list):
            return {}
        result: dict[str, str] = {}
        for item in measures:
            if not isinstance(item, dict):
                continue
            key = _as_text(item.get("metric"))
            value = _as_text(item.get("value"))
            if key:
                result[key] = value
        return result

    async def get_issue(self, issue_key: str) -> dict[str, Any] | None:
        payload = await self._request(
            method="GET",
            path="/api/issues/search",
            params={
                "issues": issue_key,
                "additionalFields": "comments",
                "ps": 1,
            },
        )
        issues = payload.get("issues")
        if not isinstance(issues, list) or not issues:
            return None
        issue = issues[0]
        if not isinstance(issue, dict):
            return None
        return issue

    async def get_issue_changelog(self, issue_key: str) -> list[dict[str, Any]]:
        payload = await self._request(
            method="GET",
            path="/api/issues/changelog",
            params={"issue": issue_key},
        )
        changelog = payload.get("changelog")
        if not isinstance(changelog, list):
            return []
        return [item for item in changelog if isinstance(item, dict)]

    async def get_source_snippet(
        self,
        *,
        component_key: str,
        from_line: int,
        to_line: int,
    ) -> str:
        payload = await self._request(
            method="GET",
            path="/api/sources/show",
            params={
                "key": component_key,
                "from": max(1, from_line),
                "to": max(1, to_line),
            },
        )
        return _extract_code_snippet(payload)

    async def get_rule(self, rule_key: str) -> dict[str, Any]:
        clean_key = rule_key.strip()
        if not clean_key:
            return {}

        now = time.monotonic()
        cached = self._rule_cache.get(clean_key)
        if cached is not None and cached[0] > now:
            return cached[1]

        async with self._rule_cache_lock:
            cached = self._rule_cache.get(clean_key)
            now = time.monotonic()
            if cached is not None and cached[0] > now:
                return cached[1]

            payload = await self._request(
                method="GET",
                path="/api/rules/show",
                params={"key": clean_key},
            )
            rule = payload.get("rule")
            result = rule if isinstance(rule, dict) else {}
            self._rule_cache[clean_key] = (now + RULE_DETAILS_CACHE_TTL_SECONDS, result)
            return result

    async def build_issue_details(
        self,
        issue: dict[str, Any],
        *,
        tab: str | None = None,
    ) -> dict[str, Any]:
        issue_key = _as_text(issue.get("key"))
        component_key = _as_text(issue.get("component"))
        file_path = _as_text(issue.get("filePath") or issue.get("file_path")) or _derive_file_path(component_key)
        line = _as_int(issue.get("line"))
        text_range = _normalize_text_range(issue.get("textRange") or issue.get("text_range"), line)
        from_line = text_range["startLine"] or line or 1
        to_line = text_range["endLine"] or line or from_line
        comments = issue.get("comments")
        if not isinstance(comments, list):
            comments = []
        tags = issue.get("tags")
        if not isinstance(tags, list):
            tags = []

        include_where = tab in {None, "whereIsTheIssue"}
        include_why = tab in {None, "whyIsThisAnIssue"}
        include_activity = tab in {None, "activity"}
        include_more_info = tab in {None, "moreInfo"}
        rule_key = _as_text(issue.get("rule"))
        rule: dict[str, Any] = {}

        if include_why or include_more_info:
            rule = await self.get_rule(rule_key)

        response: dict[str, Any] = {}

        if include_where:
            code_snippet = ""
            if component_key:
                code_snippet = await self.get_source_snippet(
                    component_key=component_key,
                    from_line=from_line,
                    to_line=to_line,
                )

            response["whereIsTheIssue"] = {
                "componentKey": component_key,
                "filePath": file_path,
                "line": line or from_line,
                "textRange": text_range,
                "codeSnippet": code_snippet,
            }

        if include_why:
            description_html = _as_text(
                rule.get("htmlDesc")
                or rule.get("htmlDescription")
                or rule.get("description")
            )
            if not description_html:
                markdown_description = _as_text(rule.get("mdDesc"))
                if markdown_description:
                    description_html = f"<pre>{html.escape(markdown_description)}</pre>"

            response["whyIsThisAnIssue"] = {
                "ruleKey": rule_key,
                "ruleName": _as_text(rule.get("name")),
                "severity": _as_text(issue.get("severity")),
                "type": _as_text(issue.get("type")),
                "tags": [tag for tag in tags if isinstance(tag, str)],
                "htmlDescription": description_html,
                "debtRemediationFunction": _as_text(
                    rule.get("debtRemFnType")
                    or rule.get("defaultDebtRemFnType")
                    or rule.get("remFnType")
                ),
            }

        if include_activity:
            activity_comments: list[dict[str, str]] = []
            for comment in comments:
                if not isinstance(comment, dict):
                    continue
                html_text = _as_text(comment.get("htmlText"))
                if not html_text:
                    markdown_text = _as_text(comment.get("markdown") or comment.get("text"))
                    if markdown_text:
                        html_text = f"<pre>{html.escape(markdown_text)}</pre>"
                activity_comments.append(
                    {
                        "key": _as_text(comment.get("key")),
                        "login": _as_text(comment.get("login")),
                        "htmlText": html_text,
                        "createdAt": _as_text(comment.get("createdAt") or comment.get("created_at")),
                    }
                )

            changelog_entries = await self.get_issue_changelog(issue_key)
            response["activity"] = {
                "comments": activity_comments,
                "changelog": [
                    {
                        "createdAt": _as_text(entry.get("creationDate") or entry.get("createdAt")),
                        "user": _as_text(entry.get("user") or entry.get("login")),
                        "diffs": [
                            {
                                "key": _as_text(diff.get("key")),
                                "oldValue": _as_text(diff.get("oldValue")),
                                "newValue": _as_text(diff.get("newValue")),
                            }
                            for diff in entry.get("diffs", [])
                            if isinstance(diff, dict)
                        ],
                    }
                    for entry in changelog_entries
                ],
            }

        if include_more_info:
            documentation_url = _as_text(rule.get("url") or rule.get("docUrl") or rule.get("doc_url"))
            response["moreInfo"] = {
                "externalRuleEngine": _as_text(
                    rule.get("engineId")
                    or rule.get("externalRuleEngine")
                )
                or None,
                "documentationUrl": documentation_url or self.build_rule_documentation_url(rule_key),
                "descriptionSections": _normalize_description_sections(rule.get("descriptionSections")),
            }

        return response
