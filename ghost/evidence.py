"""Parse participant sources into record-level, time-stamped observations."""

from __future__ import annotations

import csv
import json
import re
import shlex
import shutil
import sqlite3
import subprocess
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import tokens


RESOURCE = re.compile(r"\b(?:account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|marketing|object|legal_hold|cache|email_log|telemetry)_[A-Za-z0-9_-]+\b", re.I)
TRACE = re.compile(r"\b(?:tr|rb|rp)-\d+\b")
TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
PREFIX_SYSTEM = {
    "account": "account_service", "search": "search_service", "support": "support_platform",
    "analytics": "analytics_platform", "export": "export_service", "data_flow": "integration_service",
    "backup": "backup_service", "audit_record": "security_service", "tombstone": "identity_service",
    "marketing": "marketing_platform", "object": "object_storage", "legal_hold": "legal_service",
    "cache": "cache_service", "email_log": "notification_service", "telemetry": "analytics_platform",
}


def system_of(resource: str) -> str:
    return PREFIX_SYSTEM.get(resource.rsplit("_", 1)[0], PREFIX_SYSTEM.get(resource.split("_")[0], ""))


def system_of_table(table: str) -> str:
    for prefix, system in (("customer_profiles", "account_service"),
                           ("customer_search", "search_service"),
                           ("customer_analytics", "analytics_platform"),
                           ("support", "support_platform"),
                           ("customer_exports", "export_service")):
        if table.startswith(prefix):
            return system
    return ""


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@dataclass(frozen=True)
class Observation:
    file_id: str
    file_captured_at: str
    record_time: str
    resource_id: str
    system: str
    fields: dict
    link_tokens: frozenset[str]
    kind: str
    scope: str = ""


def observation(file_id: str, captured: str, record: dict, system: str = "", time: str = "",
                kind: str = "record", scope: str = "") -> Observation | None:
    rid = str(record.get("resource_id") or "")
    if not rid and kind != "scope":
        return None
    return Observation(file_id, captured, str(time or record.get("observed_at") or
                       record.get("recorded_at") or record.get("updated_at") or captured),
                       rid, str(system or record.get("system") or record.get("system_id") or system_of(rid)),
                       record, frozenset(tokens(record)), kind, scope)


def unpack_record(record: dict) -> dict:
    if "record_json" not in record:
        return record
    nested = record["record_json"]
    if isinstance(nested, str):
        try:
            nested = json.loads(nested)
        except ValueError:
            nested = {}
    return {**record, **nested} if isinstance(nested, dict) else record


def json_observations(file_id: str, captured: str, path: Path) -> list[Observation]:
    obj = json.loads(path.read_text(encoding="utf-8-sig"))
    out = []
    def add(record: dict, system: str = "", at: str = "", scope: str = "") -> None:
        if not isinstance(record, dict):
            return
        record = unpack_record(record)
        logical_system = record.get("system") or record.get("system_id") or system
        found = observation(file_id, captured, record, logical_system, at, scope=scope)
        if found:
            out.append(found)
    if "snapshots" in obj:
        for number, snapshot in enumerate(obj["snapshots"]):
            system = snapshot.get("data_store", "")
            at = snapshot.get("captured_at", captured)
            scope = f"{file_id}:{number}:{system}:{snapshot.get('collection','')}"
            out.append(observation(file_id, captured, {"collection": snapshot.get("collection", "")},
                                   system, at, "scope", scope))
            for record in snapshot.get("records", []):
                add(record, system, at, scope)
    elif "service_exports" in obj:
        for system, collections in obj["service_exports"].items():
            for collection, records in collections.items():
                scope = f"{file_id}:{system}:{collection}"
                out.append(observation(file_id, captured, {"collection": collection}, system,
                                       captured, "scope", scope))
                for record in records:
                    if collection == "index_queries" and isinstance(record.get("hits"), dict):
                        hits = record["hits"].get("documents", [])
                        for hit in hits:
                            add({**record, **hit, "collection": collection}, system,
                                record.get("observed_at", captured), scope)
                        if not hits and record.get("resource_id"):
                            add({**record, "collection": collection}, system,
                                record.get("observed_at", captured), scope)
                    else:
                        add({**record, "collection": collection}, system,
                            record.get("observed_at", captured), scope)
    elif "records" in obj:
        system = obj.get("source", obj.get("origin", ""))
        for record in obj["records"]:
            add(record, record.get("system", "") or system_of(record.get("resource_id", "")),
                record.get("recorded_at") or record.get("observed_at") or
                obj.get("captured_at") or obj.get("exported_at") or captured,
                f"{file_id}:{obj.get('collection',obj.get('origin','records'))}")
    return out


def sql_observations(file_id: str, captured: str, path: Path) -> list[Observation]:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.enable_load_extension(False)

    def safe_sql(action: int, first: str | None, second: str | None,
                 _database: str | None, _trigger: str | None) -> int:
        if action == sqlite3.SQLITE_PRAGMA:
            return sqlite3.SQLITE_OK if (first, second) == ("foreign_keys", "ON") else sqlite3.SQLITE_DENY
        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and second != "json_valid":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    con.set_authorizer(safe_sql)
    con.executescript(path.read_text(encoding="utf-8-sig"))
    tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    out = []
    for table in tables:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", table):
            continue
        rows = [dict(row) for row in con.execute(f'SELECT * FROM "{table}"')]
        if table == "snapshot_scope":
            for row in rows:
                system = row.get("origin_system") or row.get("system_id") or row.get("data_store") or row.get("system") or ""
                out.append(observation(file_id, captured, row, system, captured, "scope", f"{file_id}:{system}:{table}"))
            continue
        out.append(observation(file_id, captured, {"table": table}, system_of_table(table), captured,
                               "scope", f"{file_id}:{table}"))
        if table.startswith("customer_data_") and rows and "record_json" in rows[0]:
            # The SQL header describes a full point-in-time copy. An omitted account
            # can be checked against that copy even when it contains zero account rows.
            out.append(observation(file_id, captured, {"table": table, "full_copy": True},
                                   "account_service", captured, "scope", f"{file_id}:{table}:account_service"))
        for row in rows:
            row = unpack_record(row)
            row["table"] = table
            system = row.get("origin_system") or row.get("system_id") or system_of_table(table) or \
                system_of(str(row.get("resource_id", "")))
            found = observation(file_id, captured, row, system, row.get("updated_at", captured), scope=f"{file_id}:{table}")
            if found:
                out.append(found)
    con.close()
    return out


def _key_values(text: str) -> dict[str, Any]:
    """Decode quoted values in all six log envelopes, including cloud escaped payloads."""
    values = {}
    try:
        parts = shlex.split(text)
    except ValueError:
        parts = text.split()
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            value = value.strip().strip('"')
            if value in ("null", "true", "false") or re.fullmatch(r"-?(?:0|[1-9]\d*)", value):
                value = json.loads(value)
            values[key.strip()] = value
    if "message" in values and "event=" in values["message"]:
        values.update(_key_values(values["message"]))
    return values


def _log_line(line: str) -> dict[str, Any] | None:
    match = TIME.match(line)
    if not match:
        return None
    at = match.group()
    body = line[len(at):].strip()
    if body.startswith("{"):
        try:
            data = json.loads(body)
        except ValueError:
            return None
    else:
        data = _key_values(body)
        pipe = [x.strip() for x in body.split("|")]
        if len(pipe) >= 5:
            data.setdefault("service", pipe[2])
            data.setdefault("trace_id", pipe[3])
            data.setdefault("event", pipe[4])
        bracket = re.match(r"\[[A-Z]+\]\s+\[([^]]+)\]\s+\[([^]]+)\]\s+([^:]+):", body)
        if bracket:
            data.update(service=bracket[1], trace_id=bracket[2], event=bracket[3].strip())
        if body.startswith("<"):
            trace = TRACE.search(body)
            if trace:
                data.setdefault("trace_id", trace.group())
        if "event" not in data:
            event = re.search(r"\bevent=([A-Za-z_]+)", body)
            if event:
                data["event"] = event[1]
    data["_at"] = at
    if "trace_id" not in data and str(data.get("requestId", "")).startswith(("tr-", "rb-")):
        data["trace_id"] = data["requestId"]
    return data


def log_observations(file_id: str, captured: str, path: Path) -> list[Observation]:
    raw = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    lines = [_log_line(line) for line in raw]
    skipped = sum(bool(line.strip()) and parsed is None for line, parsed in zip(raw, lines))
    if skipped:
        warnings.warn(f"{file_id}: skipped {skipped} malformed log lines; source coverage is partial",
                      RuntimeWarning, stacklevel=2)
    lines = [line for line in lines if line]
    groups = defaultdict(list)
    singles = []
    for line in lines:
        trace = line.get("trace_id")
        if trace:
            groups[trace].append(line)
        elif line.get("resource_id"):
            singles.append([line])
    out = []
    for group in list(groups.values()) + singles:
        by_resource = defaultdict(list)
        subjects = set()
        for line in group:
            subjects |= tokens({key: value for key, value in line.items() if key in
                               ("lookup_key", "match_key", "subject_key", "scan_key", "correlation_key",
                                "subject_ref", "subject_reference", "matched_value", "contact_query",
                                "owner_key", "recipient_key", "contact_key", "query_key")})
            if line.get("resource_id"):
                by_resource[str(line["resource_id"])].append(line)
        for rid, observations in by_resource.items():
            fields = {}
            for line in group:
                if not line.get("resource_id") or line.get("resource_id") == rid:
                    # A lookup-cache miss describes the cache, not the later resource readback.
                    inherited = {key: value for key, value in line.items() if not
                                 (line.get("event") == "cache_lookup" and
                                  not line.get("resource_id") and key == "result")}
                    fields.update(inherited)
            fields["resource_id"] = rid
            scope = f"{file_id}:{group[0].get('trace_id',rid)}"
            source_system = fields.get("system") or fields.get("service") or fields.get("function") or ""
            if source_system.endswith("_replica"):
                source_system = system_of(rid)
            found = observation(file_id, captured, fields, source_system or system_of(rid),
                                observations[-1]["_at"], scope=scope)
            if found:
                out.append(Observation(found.file_id, found.file_captured_at, found.record_time,
                                       found.resource_id, found.system, found.fields,
                                       frozenset(set(found.link_tokens) | subjects), found.kind, found.scope))
    return out


def text_observations(file_id: str, captured: str, path: Path) -> list[Observation]:
    out = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        cols = [x.strip() for x in line.lstrip("- ").split("|")]
        if len(cols) == 6 and TIME.match(cols[0]):
            at, system, rid, category, result, subject = cols
            found = observation(file_id, captured, {"resource_id": rid, "record_type": category,
                                "result": result, "subject_reference": subject}, system, at)
            if found:
                out.append(found)
    return out


def pdf_observations(file_id: str, captured: str, path: Path,
                     links: tuple[Observation, ...] | list[Observation] = ()) -> list[Observation]:
    from pypdf import PdfReader
    out = []
    pages = list(PdfReader(path).pages)
    whole = "\n".join(page.extract_text() or "" for page in pages)
    unique_resources = set(RESOURCE.findall(whole))
    for page_number, page in enumerate(pages, 1):
        text = page.extract_text() or ""
        for line in text.splitlines():
            for rid in set(RESOURCE.findall(line)):
                context = whole if len(unique_resources) == 1 else line
                found = observation(file_id, captured, {"resource_id": rid, "text": context,
                                    "page": page_number}, time=captured, scope=f"{file_id}:page:{page_number}")
                if found:
                    out.append(found)
    # The catalog may name a PDF by its printed statement/reference number.
    for link in links:
        match = re.search(r"\(([^)]+)\)", str(link.fields.get("details", "")))
        alias = match.group(1) if match else None
        if alias and re.search(r"(?<![\w])" + re.escape(alias) + r"(?![\w])", whole) \
                and link.resource_id not in unique_resources:
            found = observation(file_id, captured,
                                {"resource_id": link.resource_id, "document_text": whole,
                                 "visible_reference": alias},
                                link.system, captured, scope=f"{file_id}:document")
            if found:
                out.append(found)
    if not out:
        out.append(observation(file_id, captured, {"document_text": whole[:2000]},
                               time=captured, kind="scope", scope=f"{file_id}:document"))
    return out


def vision_observations(file_id: str, captured: str, records: list[dict],
                        links: list[Observation]) -> list[Observation]:
    """Map validated visible IDs or exact catalog aliases to typed observations."""
    aliases = {}
    for link in links:
        match = re.search(r"\(([^)]+)\)", str(link.fields.get("details", "")))
        if match:
            aliases[match.group(1).lower()] = link.resource_id
    out = []
    for record in records:
        visible = record["resource_id"]
        rid = visible if RESOURCE.fullmatch(visible) else aliases.get(visible.lower())
        if not rid:
            continue
        fields = {**record, "resource_id": rid}
        if rid != visible:
            fields["visible_reference"] = visible
        if rid.startswith("backup_"):
            fields["image_archive_listed"] = True
        found = observation(file_id, captured, fields, system_of(rid), captured,
                            scope=f"{file_id}:image")
        if found:
            out.append(found)
    return out


def image_crosscheck(path: Path, records: list[dict]) -> list[str] | None:
    """Optionally compare reviewed visible IDs with OCR; never add decision facts."""
    executable = shutil.which("tesseract")
    if not executable:
        return None
    try:
        result = subprocess.run([executable, str(path), "stdout", "--psm", "11"],
                                capture_output=True, text=True, timeout=30, check=True)
    except (subprocess.SubprocessError, OSError) as exc:
        warnings.warn(f"Optional OCR cross-check failed for {path.name}: {exc}",
                      RuntimeWarning, stacklevel=2)
        return None
    normalized = re.sub(r"[^a-z0-9]", "", result.stdout.lower())
    return [row["resource_id"] for row in records if RESOURCE.fullmatch(row["resource_id"]) and
            re.sub(r"[^a-z0-9]", "", row["resource_id"].lower()) not in normalized]


def load(dataset: Path, vision_records: dict[str, list[dict]] | None = None,
         ocr_crosscheck: bool = False) -> tuple[list[Observation], Counter, list[dict]]:
    """Load every manifest source once; return observations and per-file coverage."""
    manifest = read_csv(dataset / "evidence_files.csv")
    observations = []
    coverage = Counter()
    links = activity_links(dataset)
    for meta in manifest:
        path = dataset / meta["file_path"]
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                found = json_observations(meta["file_id"], meta["captured_at"], path)
            elif suffix == ".sql":
                found = sql_observations(meta["file_id"], meta["captured_at"], path)
            elif suffix == ".log":
                found = log_observations(meta["file_id"], meta["captured_at"], path)
            elif suffix == ".txt":
                found = text_observations(meta["file_id"], meta["captured_at"], path)
            elif suffix == ".pdf":
                found = pdf_observations(meta["file_id"], meta["captured_at"], path, links)
            elif suffix == ".png":
                if vision_records is None or meta["file_id"] not in vision_records:
                    warnings.warn(f"{meta['file_id']}: no reviewed screenshot transcription; zero coverage",
                                  RuntimeWarning, stacklevel=2)
                    found = []
                else:
                    found = vision_observations(meta["file_id"], meta["captured_at"],
                                                vision_records[meta["file_id"]], links)
                    if ocr_crosscheck:
                        missing = image_crosscheck(path, vision_records[meta["file_id"]])
                        if missing:
                            warnings.warn(f"{meta['file_id']}: OCR did not read reviewed IDs: {missing}",
                                          RuntimeWarning, stacklevel=2)
            else:
                found = []
            observations.extend(found)
            coverage[meta["file_id"]] = len(found)
        except Exception as exc:
            if suffix in (".json", ".log"):
                warnings.warn(f"{meta['file_id']}: unreadable {suffix} source; zero coverage: {exc}",
                              RuntimeWarning, stacklevel=2)
                coverage[meta["file_id"]] = 0
                continue
            raise RuntimeError(f"Failed to parse {meta['file_id']} {path}: {exc}") from exc
    return observations, coverage, manifest


def activity_links(dataset: Path) -> list[Observation]:
    out = []
    for row in read_csv(dataset / "system_activity.csv"):
        if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        rid = row.get("resource_id") or ""
        if not rid:
            continue
        out.append(Observation(row["activity_id"], row["event_time"], row["event_time"], rid,
                               row.get("target_system") or system_of(rid), row,
                               frozenset(tokens(row.get("details", ""))), "link", "activity"))
    return out
