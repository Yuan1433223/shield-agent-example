from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DEFAULT = REPO_ROOT / "docs" / "experts" / "WLL"
DEST_DEFAULT = REPO_ROOT / "tests" / "replay" / "wll_fixtures"

FILENAME_PATTERN = re.compile(
    r"^告警分析-(?P<target>.+?)-(?P<date>\d{4}[-_]\d{2}[-_]\d{2}) "
    r"(?P<time>\d{2}_\d{2}(?:_\d{2})?)-(?P<operator>[^-]+)(?:-(?P<label>.+))?$"
)

SECTION_BOUNDS: tuple[tuple[str, str, str], ...] = (
    ("customer_info", r"1\.\s*客户信息[^\n\r]*", r"\n\s*2\.\s*发现时间"),
    ("discovery_time", r"2\.\s*发现时间[^\n\r]*", r"\n\s*3\.\s*排查思路"),
    ("process", r"3\.1\s*过程[^\n\r]*", r"\n\s*3\.2\s*结论"),
    ("conclusion", r"3\.2\s*结论[^\n\r]*", r"\n\s*4\.\s*攻击特征"),
    ("attack_features", r"4\.\s*攻击特征[^\n\r]*", r"\n\s*5\.\s*防护策略"),
    ("mitigation", r"5\.\s*防护策略[^\n\r]*", r"\n\s*6\.\s*评估AI告警的信息是否准确"),
    ("ai_review", r"6\.\s*评估AI告警的信息是否准确[^\n\r？?]*[？?]?", r"\Z"),
)

TOOL_HINTS: tuple[tuple[str, str], ...] = (
    ("ES", "elasticsearch"),
    ("ES面板", "es_dashboard"),
    ("防护日志", "protection_logs"),
    ("回源", "origin_logs"),
    ("源站", "origin_logs"),
)

TAG_HINTS: tuple[tuple[str, str], ...] = (
    ("针对特定资源", "targeted_resource"),
    ("单一路径", "single_path_focus"),
    ("UA伪造", "ua_spoofing"),
    ("不同的UA", "ua_rotation"),
    ("accept-language", "abnormal_header"),
    ("回源数量没有增加", "attack_blocked"),
    ("被拦截", "attack_blocked"),
    ("区域IP封禁", "regional_blocking"),
    ("海外", "overseas_sources"),
    ("请求数突增", "request_spike"),
    ("请求量突增", "request_spike"),
    ("请求数增加", "request_spike"),
    ("请求频率增加", "request_spike"),
    ("掉坑", "request_drop"),
    ("404", "origin_4xx"),
    ("499", "edge_499"),
    ("502", "origin_502"),
    ("503", "origin_503"),
    ("配置问题", "origin_config_issue"),
    ("应用有在调整", "origin_app_change"),
    ("重启了服务", "origin_service_restart"),
    ("未接入监控", "monitoring_gap"),
)


def normalize_text(text: str) -> str:
    text = text.replace("\ufeff", "")
    text = text.replace("\u200b", "")
    text = text.replace("\xa0", " ")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()


def slugify(value: str) -> str:
    value = re.sub(r"[^0-9A-Za-z]+", "_", value)
    value = value.strip("_").lower()
    return value or "case"


def parse_filename(path: Path) -> dict[str, Any]:
    stem = path.stem
    match = FILENAME_PATTERN.match(stem)
    if not match:
        raise ValueError(f"unsupported WLL filename format: {path.name}")

    target = match.group("target")
    date_text = match.group("date").replace("_", "-")
    time_text = match.group("time").replace("_", ":")
    if len(time_text.split(":")) == 2:
        time_text = f"{time_text}:00"

    label = (match.group("label") or "").strip()
    category = "attack" if "攻击案例" in path.parts else "non_attack"
    target_type = "ip" if "IP" in path.parts else "domain"
    case_id = f"{slugify(target)}_{date_text.replace('-', '')}_{time_text.replace(':', '')}"

    return {
        "target": target,
        "target_type": target_type,
        "operator_label": match.group("operator"),
        "source_label": label,
        "filename_alert_time": f"{date_text} {time_text}",
        "coarse_classification": category,
        "case_id": case_id,
    }


def extract_section(text: str, start_pattern: str, end_pattern: str) -> str:
    pattern = re.compile(rf"{start_pattern}\s*(?P<body>.*?)(?={end_pattern})", re.S)
    match = pattern.search(text)
    if not match:
        return ""

    body = match.group("body").strip()
    lines = [line.strip() for line in body.split("\n")]
    compact = [line for line in lines if line]
    return "\n".join(compact)


def extract_sections(text: str) -> dict[str, str]:
    return {
        name: extract_section(text, start_pattern, end_pattern)
        for name, start_pattern, end_pattern in SECTION_BOUNDS
    }


def extract_named_time(text: str, label: str) -> str | None:
    pattern = re.compile(rf"{re.escape(label)}[:：]\s*([0-9/_:\- ]+)")
    match = pattern.search(text)
    if not match:
        return None

    return match.group(1).replace("/", "-").strip()


def extract_inline_value(text: str, label: str) -> str | None:
    pattern = re.compile(rf"{re.escape(label)}[:：]\s*([^\n]+)")
    match = pattern.search(text)
    if not match:
        return None

    return match.group(1).strip()


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = value.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        result.append(clean)
    return result


def extract_urls(text: str) -> list[str]:
    matches = re.findall(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+", text)
    filtered = []
    for item in matches:
        item = item.rstrip("。，；、,.")
        if item == "/":
            continue
        if "/" not in item[1:] and "_" not in item:
            continue
        if len(item) < 5:
            continue
        filtered.append(item)
    return dedupe_keep_order(filtered)


def extract_investigation_steps(section: str) -> list[str]:
    steps: list[str] = []
    for line in section.split("\n"):
        clean = line.strip("• ").strip()
        if not clean:
            continue
        if re.match(r"^\d+\.", clean):
            steps.append(clean)
            continue
        if clean.startswith("•") or clean.startswith("◦"):
            steps.append(clean.lstrip("•◦ ").strip())
            continue
        if any(token in clean for token in ("查看", "分析", "过滤", "对比", "发现", "判断")) and len(clean) >= 10:
            steps.append(clean)
    return dedupe_keep_order(steps)


def extract_mitigation_actions(section: str) -> list[str]:
    actions: list[str] = []
    for line in section.split("\n"):
        clean = line.strip("•◦ ").strip()
        if not clean:
            continue
        if len(clean) < 4:
            continue
        actions.append(clean)
    return dedupe_keep_order(actions)


def extract_attack_type(section: str, coarse_classification: str) -> tuple[str, str]:
    raw_label = extract_inline_value(section, "攻击类型")
    if raw_label:
        normalized = raw_label.replace(" ", "")
    elif "非攻击导致" in section or coarse_classification == "non_attack":
        normalized = "非攻击导致"
    elif "CC攻击" in section:
        normalized = "CC攻击"
    else:
        normalized = "未知"

    if "非攻击" in normalized:
        normalized = "非攻击导致"
        attack_type = "non_attack"
    elif "CC" in normalized:
        normalized = "CC攻击"
        attack_type = "cc_attack"
    elif "打节点" in normalized:
        normalized = "打节点攻击"
        attack_type = "node_pressure_attack"
    else:
        attack_type = slugify(normalized)

    return attack_type, normalized


def extract_feature_tags(section: str) -> list[str]:
    tags: list[str] = []
    line_value = extract_inline_value(section, "关键特征标签")
    if line_value:
        for part in re.split(r"[、,，\s]+", line_value):
            clean = part.strip()
            if clean:
                tags.append(clean)

    for line in section.split("\n"):
        clean = line.strip("•◦ ").strip()
        if re.match(r"^\d+\.", clean):
            continue
        if "：" in clean and len(clean) <= 30:
            name = clean.split("：", 1)[0].strip()
            if name and name != "攻击类型":
                tags.append(name)

    return dedupe_keep_order(tags)


def infer_tools(text: str) -> list[str]:
    tools: list[str] = []
    for token, tool_name in TOOL_HINTS:
        if token in text:
            tools.append(tool_name)
    return dedupe_keep_order(tools)


def infer_status_origin(text: str) -> str:
    if "高防节点" in text and ("源站响应" in text or "源站" in text):
        return "mixed_edge_origin"
    if any(token in text for token in ("源站响应", "源站服务器", "源站服务", "upstream_status", "回源")):
        return "origin"
    if any(token in text for token in ("高防节点", "防护日志", "区域IP封禁", "拦截")):
        return "edge_or_protection"
    return "unknown"


def infer_temporal_relation(classification: str, text: str) -> str:
    if classification == "non_attack":
        if any(token in text for token in ("配置问题", "应用有在调整", "重启了服务", "暂停使用", "恢复正常")):
            return "origin_change_then_status_change"
        if any(token in text for token in ("404状态码", "响应404", "响应503")):
            return "origin_status_directly_returned"
        return "non_attack_unknown"

    if any(token in text for token in ("回源数量没有增加", "已被拦截", "未造成影响", "区域IP封禁")):
        return "attack_blocked_before_origin_impact"
    if any(token in text for token in ("导致源站", "回源量有增加", "源站受影响", "业务请求量有增加")):
        return "attack_pressure_then_origin_errors"
    if "打节点" in text:
        return "node_pressure_then_service_degrade"
    return "attack_unknown"


def infer_evidence_tags(text: str, feature_tags: list[str], urls: list[str]) -> list[str]:
    tags = list(feature_tags)
    for token, tag_name in TAG_HINTS:
        if token in text:
            tags.append(tag_name)
    if urls:
        tags.append("url_level_evidence")
    return dedupe_keep_order(tags)


def extract_ai_improvement(section: str) -> str:
    if "建议AI分析优化点" not in section:
        return ""
    _, improvement = section.split("建议AI分析优化点", 1)
    for marker in ("AI分析结果", "AI分析情况"):
        if marker in improvement:
            improvement = improvement.split(marker, 1)[0]
    return improvement.lstrip("：:\n ").strip()


def extract_ai_review_notes(section: str) -> str:
    lines: list[str] = []
    for line in section.split("\n"):
        clean = line.strip()
        if not clean:
            continue
        if clean.startswith("1. AI 告警情况") or clean.startswith("2. 准确性评估"):
            continue
        if "AI分析结果" in clean or "AI分析情况" in clean:
            break
        lines.append(clean)
    return "\n".join(lines).strip()


def backfill_missing_sections(metadata: dict[str, Any], sections: dict[str, str]) -> dict[str, str]:
    if sections["conclusion"]:
        return sections

    summary_parts = [
        "未抽取到独立结论段，按文档目录和已有排查过程做降级归纳。",
        "该案例目录分类为攻击案例。"
        if metadata["coarse_classification"] == "attack"
        else "该案例目录分类为非攻击案例。",
    ]
    process = sections.get("process", "")
    if "503" in process or "502" in process or "499" in process:
        summary_parts.append("过程证据显示异常状态码以源站或节点超时类响应为主。")
    if "源站IP" in process:
        summary_parts.append("过程证据提示异常 IP 可能就是源站侧实体。")
    if "请求集中在" in process:
        summary_parts.append("过程证据已定位到集中异常 URL。")
    sections["conclusion"] = " ".join(summary_parts)

    if not sections["attack_features"]:
        sections["attack_features"] = (
            "1. 攻击类型：CC攻击"
            if metadata["coarse_classification"] == "attack"
            else "1. 攻击类型：非攻击导致"
        )

    return sections


def build_fixture(source_root: Path, path: Path) -> dict[str, Any]:
    metadata = parse_filename(path)
    raw_text = path.read_text(encoding="utf-8")
    text = normalize_text(raw_text)
    sections = backfill_missing_sections(metadata, extract_sections(text))

    conclusion = sections["conclusion"]
    feature_section = sections["attack_features"]
    mitigation_section = sections["mitigation"]
    ai_section = sections["ai_review"]
    operational_text = "\n".join(
        part for part in (sections["process"], conclusion, feature_section, mitigation_section) if part
    )
    full_signal_text = "\n".join(part for part in (operational_text, ai_section) if part)

    attack_type, attack_type_label = extract_attack_type(
        feature_section,
        coarse_classification=metadata["coarse_classification"],
    )
    final_classification = "non_attack" if "非攻击" in attack_type_label else metadata["coarse_classification"]
    urls = extract_urls(operational_text)
    feature_tags = extract_feature_tags(feature_section)

    fixture = {
        "case_id": metadata["case_id"],
        "operator": "wang_longlong",
        "operator_label": metadata["operator_label"],
        "source_file": path.relative_to(source_root).as_posix(),
        "source_label": metadata["source_label"],
        "source_category": metadata["coarse_classification"],
        "target": metadata["target"],
        "target_type": metadata["target_type"],
        "abnormal_object": metadata["target"],
        "alert_time": extract_named_time(text, "安全助手告警的时间") or metadata["filename_alert_time"],
        "customer_feedback_time": extract_named_time(text, "客户反馈时间")
        or extract_named_time(text, "客户反馈的时间"),
        "final_classification": final_classification,
        "classification_reason": conclusion[:300],
        "attack_type": attack_type,
        "attack_type_label": attack_type_label,
        "status_origin": infer_status_origin(full_signal_text),
        "temporal_relation": infer_temporal_relation(final_classification, full_signal_text),
        "tools_used": infer_tools(full_signal_text),
        "targeted_paths": urls,
        "key_feature_tags": feature_tags,
        "evidence_tags": infer_evidence_tags(full_signal_text, feature_tags, urls),
        "investigation_steps": extract_investigation_steps(sections["process"]),
        "mitigation_actions": extract_mitigation_actions(mitigation_section),
        "ai_alert_status": extract_inline_value(ai_section, "AI 告警情况"),
        "ai_accuracy": extract_inline_value(ai_section, "准确性评估"),
        "ai_review_notes": extract_ai_review_notes(ai_section),
        "ai_improvement_advice": extract_ai_improvement(ai_section),
        "sections": sections,
    }
    return fixture


def build_all(source_root: Path) -> list[dict[str, Any]]:
    fixtures = [build_fixture(source_root, path) for path in sorted(source_root.rglob("*.txt"))]
    return fixtures


def write_fixtures(fixtures: list[dict[str, Any]], dest_root: Path, source_root: Path) -> None:
    dest_root.mkdir(parents=True, exist_ok=True)
    for old_file in dest_root.glob("*.json"):
        old_file.unlink()

    for fixture in fixtures:
        out_path = dest_root / f"{fixture['case_id']}.json"
        out_path.write_text(json.dumps(fixture, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    tag_counts = Counter(tag for fixture in fixtures for tag in fixture["evidence_tags"])
    accuracy_counts = Counter(fixture["ai_accuracy"] or "unknown" for fixture in fixtures)
    classification_counts = Counter(fixture["final_classification"] for fixture in fixtures)
    target_type_counts = Counter(fixture["target_type"] for fixture in fixtures)
    status_origin_counts = Counter(fixture["status_origin"] for fixture in fixtures)
    temporal_relation_counts = Counter(fixture["temporal_relation"] for fixture in fixtures)
    attack_type_counts = Counter(fixture["attack_type_label"] for fixture in fixtures)

    index = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source_root": str(source_root),
        "case_count": len(fixtures),
        "classification_counts": dict(classification_counts),
        "target_type_counts": dict(target_type_counts),
        "status_origin_counts": dict(status_origin_counts),
        "temporal_relation_counts": dict(temporal_relation_counts),
        "attack_type_counts": dict(attack_type_counts),
        "ai_accuracy_counts": dict(accuracy_counts),
        "evidence_tag_counts": dict(tag_counts),
        "cases": [
            {
                "case_id": fixture["case_id"],
                "target": fixture["target"],
                "final_classification": fixture["final_classification"],
                "attack_type": fixture["attack_type"],
                "ai_accuracy": fixture["ai_accuracy"],
                "source_file": fixture["source_file"],
            }
            for fixture in fixtures
        ],
    }
    (dest_root / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build structured WLL replay fixtures from extracted TXT files.")
    parser.add_argument("--src", type=Path, default=SOURCE_DEFAULT)
    parser.add_argument("--dst", type=Path, default=DEST_DEFAULT)
    args = parser.parse_args()

    fixtures = build_all(args.src)
    write_fixtures(fixtures, args.dst, args.src)
    print(f"built {len(fixtures)} WLL fixtures -> {args.dst}")


if __name__ == "__main__":
    main()
