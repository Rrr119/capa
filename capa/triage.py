# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Batch triage for directories of malware samples.

The triage pass is intentionally file-scoped: it parses PE/ELF headers and
imports, extracts strings, and evaluates capa file-scope rules. This is fast
enough for daily batches and provides useful context without disassembling
every sample.
"""

import io
import os
import re
import sys
import json
import time
import hashlib
import logging
import argparse
import traceback
from typing import Any, Optional
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from collections.abc import Mapping

import pefile
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import InterpSegment

import capa.rules
from capa.rules import Rule, Scope, RuleSet
from capa.engine import FeatureSet
from capa.features.file import Export as ExportFeature
from capa.features.file import Import as ImportFeature
from capa.features.file import Section as SectionFeature
from capa.features.common import (
    OS,
    FORMAT_PE,
    FORMAT_ELF,
    OS_WINDOWS,
    Arch,
    Format,
    String,
)
from capa.features.address import NO_ADDRESS, FileOffsetAddress
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.strings import extract_ascii_strings, extract_unicode_strings

logger = logging.getLogger("capa.triage")

TRIAGE_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 1

E_MISSING_RULES = 10
E_MISSING_FILE = 11
E_INVALID_RULE = 12

DEFAULT_HIGH_RISK_NAMESPACES = (
    "anti-analysis/",
    "command-and-control/",
    "credential-access/",
    "data-manipulation/encryption/",
    "defense-evasion/",
    "exfiltration/",
    "impact/",
    "lateral-movement/",
    "persistence/",
    "privilege-escalation/",
)

# ATT&CK techniques that generally warrant prompt review during triage.
DEFAULT_HIGH_RISK_TECHNIQUES = frozenset({
    "T1003",  # OS Credential Dumping
    "T1021",  # Remote Services
    "T1027",  # Obfuscated Files or Information
    "T1041",  # Exfiltration Over C2 Channel
    "T1047",  # Windows Management Instrumentation
    "T1053",  # Scheduled Task/Job
    "T1055",  # Process Injection
    "T1059",  # Command and Scripting Interpreter
    "T1068",  # Exploitation for Privilege Escalation
    "T1070",  # Indicator Removal
    "T1071",  # Application Layer Protocol
    "T1078",  # Valid Accounts
    "T1090",  # Proxy
    "T1105",  # Ingress Tool Transfer
    "T1112",  # Modify Registry
    "T1134",  # Access Token Manipulation
    "T1136",  # Create Account
    "T1140",  # Deobfuscate/Decode Files or Information
    "T1197",  # BITS Jobs
    "T1218",  # System Binary Proxy Execution
    "T1485",  # Data Destruction
    "T1486",  # Data Encrypted for Impact
    "T1490",  # Inhibit System Recovery
    "T1497",  # Virtualization/Sandbox Evasion
    "T1543",  # Create or Modify System Process
    "T1546",  # Event Triggered Execution
    "T1547",  # Boot or Logon Autostart Execution
    "T1548",  # Abuse Elevation Control Mechanism
    "T1552",  # Unsecured Credentials
    "T1553",  # Subvert Trust Controls
    "T1555",  # Credentials from Password Stores
    "T1562",  # Impair Defenses
    "T1564",  # Hide Artifacts
    "T1567",  # Exfiltration Over Web Service
    "T1570",  # Lateral Tool Transfer
    "T1574",  # Hijack Execution Flow
})

ATTACK_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _build_suspicious_imports() -> dict[str, tuple[str, ...]]:
    categories = {
        "process injection": (
            "createremotethread",
            "createremotethreadex",
            "virtualallocex",
            "virtualprotectex",
            "writeprocessmemory",
            "ntwritevirtualmemory",
            "ntcreatethreadex",
            "rtlcreateuserthread",
            "queueuserapc",
            "setthreadcontext",
            "mapviewofsection",
            "ntmapviewofsection",
            "openprocess",
        ),
        "anti-analysis": (
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "ntqueryinformationprocess",
            "findwindow",
            "ptrace",
        ),
        "credential access": (
            "credread",
            "credenumerate",
            "lsaopenpolicy",
            "lsaenumeratetrusteddomain",
            "logonuser",
            "netusergetinfo",
            "netlocalgroupgetmembers",
            "samqueryinformationuser",
            "getpwnam",
            "getpwuid",
            "getspnam",
            "crypt",
        ),
        "privilege escalation": (
            "adjusttokenprivileges",
            "openthreadtoken",
            "openprocesstoken",
            "lookupprivilegevalue",
            "impersonateloggedonuser",
            "createprocesswithtokenw",
            "settokeninformation",
            "setuid",
            "setgid",
            "seteuid",
            "setegid",
            "setresuid",
            "capset",
        ),
        "persistence": (
            "createservice",
            "openscmanager",
            "startservice",
            "changeserviceconfig",
            "setwindowshookex",
            "setwindowshookexa",
            "setwindowshookexw",
        ),
        "network access": (
            "internetopen",
            "internetopenurl",
            "internetconnect",
            "httpsendrequest",
            "httpopenrequest",
            "winhttpopen",
            "winhttpconnect",
            "winhttpsendrequest",
            "urldownloadtofile",
            "wsastartup",
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "getaddrinfo",
            "gethostbyname",
            "dnsquery",
            "curl_easy_init",
        ),
        "cryptography": (
            "cryptencrypt",
            "cryptdecrypt",
            "cryptgenkey",
            "cryptacquirecontext",
            "bcryptencrypt",
            "bcryptdecrypt",
            "bcryptgeneratesymmetrickey",
        ),
        "execution": (
            "system",
            "popen",
            "execl",
            "execle",
            "execlp",
            "execv",
            "execve",
            "execvp",
            "posix_spawn",
        ),
        "dynamic loading": (
            "dlopen",
            "dlmopen",
            "dlsym",
        ),
        "memory manipulation": (
            "memfd_create",
            "process_vm_readv",
            "process_vm_writev",
        ),
        "filesystem manipulation": (
            "deletefile",
            "deletefilea",
            "deletefilew",
            "unlink",
            "remove",
            "truncate",
        ),
        "lateral movement": (
            "wnetaddconnection",
            "wnetaddconnection2",
            "netuseadd",
            "netuseradd",
            "netlocalgroupaddmembers",
        ),
    }

    ret: dict[str, tuple[str, ...]] = {}
    for category, names in categories.items():
        for name in names:
            ret.setdefault(name, ())
            ret[name] = (*ret[name], category)
    return ret


SUSPICIOUS_IMPORTS = _build_suspicious_imports()


class TriageError(Exception):
    """base class for expected triage failures."""


class MissingRulesError(TriageError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso_from_unix_timestamp(timestamp: int) -> Optional[str]:
    if timestamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def hex_value(value: int) -> str:
    return f"0x{value:X}"


def decode_c_string(value: Optional[bytes]) -> str:
    if not value:
        return ""
    return value.partition(b"\x00")[0].decode("utf-8", errors="replace")


def normalize_import_name(name: str) -> str:
    name = name.rsplit("!", 1)[-1].rsplit(".", 1)[-1].lower()
    name = name.removeprefix("__imp_").lstrip("_")
    return name.partition("@")[0]


def suspicious_import_categories(name: str) -> tuple[str, ...]:
    return SUSPICIOUS_IMPORTS.get(normalize_import_name(name), ())


def make_import_entry(name: str, ordinal: Optional[int] = None, module: Optional[str] = None) -> dict[str, Any]:
    categories = suspicious_import_categories(name)
    entry: dict[str, Any] = {
        "name": name,
        "suspicious": bool(categories),
        "categories": list(categories),
    }
    if module:
        entry["module"] = module
    if ordinal is not None:
        entry["ordinal"] = ordinal
    return entry


def detect_file_type(buf: bytes) -> str:
    if buf.startswith(b"MZ"):
        return "pe"
    if buf.startswith(b"\x7fELF"):
        return "elf"
    return "other"


def parse_pe(buf: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str]]:
    pe = pefile.PE(data=buf, fast_load=False)
    try:
        fh = pe.FILE_HEADER
        oh = pe.OPTIONAL_HEADER
        machine_name = pefile.MACHINE_TYPE.get(fh.Machine, hex_value(fh.Machine))
        subsystem_name = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, hex_value(oh.Subsystem))
        image_base = int(getattr(oh, "ImageBase", 0) or 0)
        entry_point = int(getattr(oh, "AddressOfEntryPoint", 0) or 0)

        header: dict[str, Any] = {
            "format": "pe",
            "magic": "PE32+" if oh.Magic == 0x20B else "PE32",
            "machine": machine_name,
            "machine_id": hex_value(fh.Machine),
            "timestamp": int(fh.TimeDateStamp),
            "timestamp_utc": iso_from_unix_timestamp(int(fh.TimeDateStamp)),
            "characteristics": hex_value(fh.Characteristics),
            "is_dll": bool(fh.Characteristics & 0x2000),
            "is_executable": bool(fh.Characteristics & 0x0002),
            "subsystem": subsystem_name,
            "image_base": hex_value(image_base),
            "entry_point_rva": hex_value(entry_point),
            "entry_point_va": hex_value(image_base + entry_point),
            "section_count": int(fh.NumberOfSections),
            "size_of_image": hex_value(int(getattr(oh, "SizeOfImage", 0) or 0)),
            "checksum": hex_value(int(getattr(oh, "CheckSum", 0) or 0)),
            "has_imports": hasattr(pe, "DIRECTORY_ENTRY_IMPORT"),
            "has_delay_imports": hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"),
            "has_exports": hasattr(pe, "DIRECTORY_ENTRY_EXPORT"),
            "has_debug": hasattr(pe, "DIRECTORY_ENTRY_DEBUG"),
            "has_resources": hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"),
            "has_relocations": hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"),
            "has_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
            "has_signature": hasattr(pe, "DIRECTORY_ENTRY_SECURITY"),
        }

        sections: list[dict[str, Any]] = []
        for section in pe.sections:
            sections.append({
                "name": decode_c_string(section.Name),
                "virtual_address": hex_value(int(section.VirtualAddress)),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_offset": hex_value(int(section.PointerToRawData)),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": hex_value(int(section.Characteristics)),
            })

        libraries: dict[str, list[dict[str, Any]]] = {}
        suspicious: list[dict[str, Any]] = []
        import_count = 0
        import_directories = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_directories.extend(pe.DIRECTORY_ENTRY_IMPORT)
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            import_directories.extend(pe.DIRECTORY_ENTRY_DELAY_IMPORT)

        for dll in import_directories:
            module = decode_c_string(dll.dll) or "<unknown>"
            module_imports: list[dict[str, Any]] = []
            for imp in dll.imports:
                if imp.name:
                    name = decode_c_string(imp.name)
                    ordinal = None
                else:
                    ordinal = int(imp.ordinal) if imp.ordinal is not None else 0
                    name = f"#{ordinal}"

                entry = make_import_entry(name, ordinal=ordinal if not imp.name else None, module=module)
                module_imports.append(entry)
                if entry["suspicious"]:
                    suspicious.append(entry)
                import_count += 1

            module_imports.sort(key=lambda item: item["name"].lower())
            libraries[module] = sorted(
                libraries.get(module, []) + module_imports, key=lambda item: item["name"].lower()
            )

        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.name:
                    exports.append(decode_c_string(export.name))

        suspicious.sort(key=lambda item: (item["module"].lower(), item["name"].lower()))
        imports = {
            "count": import_count,
            "libraries": dict(sorted(libraries.items(), key=lambda item: item[0].lower())),
            "suspicious": suspicious,
        }
        return header, sections, imports, sorted(set(exports), key=str.lower)
    finally:
        pe.close()


def parse_elf(
    buf: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], list[str]]:
    elf = ELFFile(io.BytesIO(buf))
    elf_header = elf.header
    ident = elf_header["e_ident"]
    raw_machine = elf_header["e_machine"]
    machine: str
    machine_id: str | None
    if isinstance(raw_machine, int):
        machine = ELF_MACHINE_NAME.get(raw_machine, hex_value(raw_machine))
        machine_id = hex_value(raw_machine)
    else:
        machine = str(raw_machine)
        machine_number = ELF_MACHINE_ID.get(machine)
        machine_id = hex_value(machine_number) if machine_number is not None else None

    header: dict[str, Any] = {
        "format": "elf",
        "class": ident["EI_CLASS"],
        "endianness": ident["EI_DATA"],
        "os_abi": ident["EI_OSABI"],
        "type": elf_header["e_type"],
        "machine": machine,
        "machine_id": machine_id,
        "entry_point": hex_value(int(elf_header["e_entry"])),
        "program_header_count": int(elf_header["e_phnum"]),
        "section_header_count": int(elf_header["e_shnum"]),
        "interpreter": None,
        "dependencies": [],
    }

    sections: list[dict[str, Any]] = []
    for index in range(elf.num_sections()):
        try:
            section = elf.get_section(index)
            sections.append({
                "name": section.name,
                "type": section["sh_type"],
                "address": hex_value(int(section["sh_addr"])),
                "offset": hex_value(int(section["sh_offset"])),
                "size": int(section["sh_size"]),
            })
        except Exception as e:
            logger.debug("failed to parse ELF section %d: %s", index, e)

    segments: list[dict[str, Any]] = []
    for index in range(elf.num_segments()):
        try:
            segment = elf.get_segment(index)
            segment_type = segment["p_type"]
            segments.append({
                "type": segment_type,
                "flags": segment["p_flags"],
                "offset": hex_value(int(segment["p_offset"])),
                "virtual_address": hex_value(int(segment["p_vaddr"])),
                "file_size": int(segment["p_filesz"]),
                "memory_size": int(segment["p_memsz"]),
                "alignment": int(segment["p_align"]),
            })

            if isinstance(segment, InterpSegment):
                try:
                    header["interpreter"] = segment.get_interp_name()
                except Exception as e:
                    logger.debug("failed to read ELF interpreter: %s", e)

            if isinstance(segment, DynamicSegment):
                try:
                    dependencies = set()
                    for tag in segment.iter_tags():
                        needed = getattr(tag, "needed", None)
                        if tag.entry.d_tag == "DT_NEEDED" and isinstance(needed, str):
                            dependencies.add(needed)
                    header["dependencies"] = sorted(dependencies)
                except Exception as e:
                    logger.debug("failed to read ELF dependencies: %s", e)
        except Exception as e:
            logger.debug("failed to parse ELF segment %d: %s", index, e)

    import_names: set[str] = set()
    try:
        from capa.features.extractors.elffile import extract_file_import_names

        import_names = {str(feature.value) for feature, _ in extract_file_import_names(elf)}
    except Exception as e:
        logger.debug("failed to extract ELF imports: %s", e)

    export_names: set[str] = set()
    try:
        from capa.features.extractors.elffile import extract_file_export_names

        export_names = {str(feature.value) for feature, _ in extract_file_export_names(elf)}
    except Exception as e:
        logger.debug("failed to extract ELF exports: %s", e)

    dynamic_imports = [make_import_entry(name, module="<dynamic>") for name in sorted(import_names, key=str.lower)]
    suspicious = [entry for entry in dynamic_imports if entry["suspicious"]]
    imports = {
        "count": len(dynamic_imports),
        "libraries": {"<dynamic>": dynamic_imports},
        "suspicious": suspicious,
    }
    return header, sections, segments, imports, sorted(export_names, key=str.lower)


def parse_other(buf: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str]]:
    encoding = None
    if buf:
        try:
            buf.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            pass

    header = {
        "format": "other",
        "magic": buf[:8].hex(),
        "size": len(buf),
        "text_encoding": encoding,
    }
    imports = {"count": 0, "libraries": {}, "suspicious": []}
    return header, [], imports, []


def extract_strings(
    buf: bytes, min_length: int, max_strings: int
) -> tuple[list[tuple[int, str, str]], list[dict[str, Any]], int]:
    strings: list[tuple[int, str, str]] = []
    for item in extract_ascii_strings(buf, n=min_length):
        strings.append((item.offset, "ascii", item.s))
    for item in extract_unicode_strings(buf, n=min_length):
        strings.append((item.offset, "utf-16le", item.s))

    strings.sort(key=lambda item: (item[0], item[1]))
    total = len(strings)
    all_strings = strings
    if max_strings > 0:
        display_strings = strings[:max_strings]
    else:
        display_strings = strings

    stored = [
        {
            "offset": hex_value(offset),
            "encoding": encoding,
            "value": value,
        }
        for offset, encoding, value in display_strings
    ]
    return (
        all_strings,
        stored,
        total,
    )


def arch_for_pe(machine: int) -> Optional[str]:
    if machine == 0x14C:
        return "i386"
    if machine == 0x8664:
        return "amd64"
    if machine == 0xAA64:
        return "aarch64"
    if machine == 0x1C0:
        return "arm"
    return None


ELF_MACHINE_ARCH = {
    "EM_386": "i386",
    "EM_X86_64": "amd64",
    "EM_ARM": "arm",
    "EM_AARCH64": "aarch64",
    "EM_MIPS": "mips",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_RISCV": "riscv",
}

ELF_MACHINE_ID = {
    "EM_386": 3,
    "EM_MIPS": 8,
    "EM_PPC": 20,
    "EM_PPC64": 21,
    "EM_ARM": 40,
    "EM_X86_64": 62,
    "EM_AARCH64": 183,
    "EM_RISCV": 243,
}

ELF_MACHINE_NAME = {number: name for name, number in ELF_MACHINE_ID.items()}


def add_feature(features: FeatureSet, feature: Any, address: Any = NO_ADDRESS) -> None:
    features[feature].add(address)


def build_feature_set(
    buf: bytes,
    file_type: str,
    header: dict[str, Any],
    sections: list[dict[str, Any]],
    imports: dict[str, Any],
    exports: list[str],
    strings: list[tuple[int, str, str]],
) -> FeatureSet:
    features: FeatureSet = defaultdict(set)

    if file_type == "pe":
        add_feature(features, Format(FORMAT_PE))
        add_feature(features, OS(OS_WINDOWS))
        machine_id = int(header["machine_id"], 16)
        arch = arch_for_pe(machine_id)
        if arch:
            add_feature(features, Arch(arch))
    elif file_type == "elf":
        add_feature(features, Format(FORMAT_ELF))
        arch = ELF_MACHINE_ARCH.get(header["machine"])
        if arch:
            add_feature(features, Arch(arch))

        try:
            from capa.features.extractors.common import extract_os

            for feature, address in extract_os(buf):
                add_feature(features, feature, address)
        except Exception as e:
            logger.debug("failed to detect ELF OS: %s", e)

    for section in sections:
        name = section.get("name")
        if name:
            add_feature(features, SectionFeature(name))

    for name in exports:
        add_feature(features, ExportFeature(name))

    for module, module_imports in imports.get("libraries", {}).items():
        if module == "<dynamic>":
            for entry in module_imports:
                add_feature(features, ImportFeature(entry["name"]))
            continue

        module_name = module.rpartition(".")[0].lower()
        for entry in module_imports:
            for name in generate_symbols(module_name, entry["name"], include_dll=True):
                add_feature(features, ImportFeature(name))

    for offset, _, value in strings:
        add_feature(features, String(value), FileOffsetAddress(offset))

    return features


def metadata_values(meta: dict[str, Any], key: str) -> list[str]:
    value = meta.get(key)
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def rule_high_risk_reasons(rule: Rule, config: "TriageConfig") -> list[str]:
    reasons: list[str] = []
    meta = rule.meta

    severity = str(meta.get("severity", "")).strip().lower()
    if severity in ("high", "critical"):
        reasons.append(f"rule severity is {severity}")

    risk = str(meta.get("risk", "")).strip().lower()
    if risk in ("high", "critical"):
        reasons.append(f"rule risk is {risk}")

    for key in ("capa/high-risk", "high_risk", "high-risk"):
        if meta.get(key) is True:
            reasons.append(f"rule metadata {key}=true")

    namespace = str(meta.get("namespace", "")).strip()
    for prefix in config.high_risk_namespaces:
        if namespace == prefix.rstrip("/") or namespace.startswith(prefix):
            reasons.append(f"rule namespace {namespace or '<none>'} matches {prefix}")
            break

    for attack in metadata_values(meta, "att&ck"):
        for technique in ATTACK_TECHNIQUE_RE.findall(attack):
            if technique in config.high_risk_techniques:
                reasons.append(f"rule references high-risk ATT&CK technique {technique}")

    return list(dict.fromkeys(reasons))


def describe_matches(matches: Mapping[str, Any], config: "TriageConfig") -> list[dict[str, Any]]:
    assert config.ruleset is not None
    described: list[dict[str, Any]] = []
    for name in sorted(matches):
        rule = config.ruleset.rules[name]
        reasons = rule_high_risk_reasons(rule, config)
        meta = rule.meta
        described.append({
            "name": rule.name,
            "namespace": str(meta.get("namespace", "")),
            "description": str(meta.get("description", "")),
            "attack": metadata_values(meta, "att&ck"),
            "mbc": metadata_values(meta, "mbc"),
            "high_risk": bool(reasons),
            "high_risk_reasons": reasons,
        })
    return described


def match_deep_rules(path: Path, file_type: str, config: "TriageConfig") -> Mapping[str, Any]:
    assert config.ruleset is not None

    import capa.loader
    from capa.capabilities.common import find_capabilities

    input_format = FORMAT_PE if file_type == "pe" else FORMAT_ELF
    extractor = capa.loader.get_extractor(
        path,
        input_format,
        capa.loader.get_os(path),
        capa.loader.BACKEND_VIV,
        [],
        should_save_workspace=False,
        disable_progress=True,
        sample_path=path,
    )
    capabilities = find_capabilities(config.ruleset, extractor, disable_progress=True)
    return capabilities.matches


def file_fingerprint(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"size": int(stat.st_size), "mtime_ns": int(stat.st_mtime_ns)}


def sha256_bytes(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def analyze_file(path: Path, relative_path: str, config: "TriageConfig") -> dict[str, Any]:
    started = time.monotonic()
    buf = path.read_bytes()
    file_type = detect_file_type(buf)

    sections: list[dict[str, Any]]
    segments: list[dict[str, Any]] = []
    if file_type == "pe":
        header, sections, imports, exports = parse_pe(buf)
    elif file_type == "elf":
        header, sections, segments, imports, exports = parse_elf(buf)
    else:
        header, sections, imports, exports = parse_other(buf)

    all_strings, stored_strings, string_count = extract_strings(buf, config.string_min_length, config.max_strings)
    features = build_feature_set(buf, file_type, header, sections, imports, exports, all_strings)

    if config.ruleset is not None and config.deep and file_type in ("pe", "elf"):
        matches = match_deep_rules(path, file_type, config)
    elif config.ruleset is not None:
        _, matches = config.ruleset.match(Scope.FILE, features, NO_ADDRESS)
    else:
        matches = {}

    described_matches = describe_matches(matches, config) if config.ruleset is not None else []
    high_risk_rules = [match for match in described_matches if match["high_risk"]]
    suspicious_imports = imports.get("suspicious", [])

    risk_reasons: list[str] = []
    for match in high_risk_rules:
        detail = "; ".join(match["high_risk_reasons"]) or "rule marked high risk"
        risk_reasons.append(f"matched high-risk rule '{match['name']}' ({detail})")
    for entry in suspicious_imports:
        categories = ", ".join(entry["categories"])
        risk_reasons.append(f"suspicious import {entry['module']}!{entry['name']} ({categories})")

    high_risk = bool(risk_reasons)
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "relative_path": relative_path,
        "name": path.name,
        "file_type": file_type,
        "status": "ok",
        "size": int(stat.st_size),
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        "sha256": sha256_bytes(buf),
        "header": header,
        "sections": sections,
        "segments": segments,
        "imports": imports,
        "exports": exports,
        "strings": {
            "count": string_count,
            "returned": len(stored_strings),
            "truncated": string_count > len(stored_strings),
            "items": stored_strings,
        },
        "rules": {
            "scope": "full" if config.deep and file_type in ("pe", "elf") else "file",
            "matched_count": len(described_matches),
            "high_risk_count": len(high_risk_rules),
            "matches": described_matches,
        },
        "risk": {
            "level": "high" if high_risk else "none",
            "highlight": high_risk,
            "color": "red" if high_risk else None,
            "reasons": risk_reasons,
        },
        "analysis_duration_ms": round((time.monotonic() - started) * 1000),
        "analyzed_at": utc_now(),
    }


def failure_record(path: Path, relative_path: str, error: BaseException, attempts: int) -> dict[str, Any]:
    file_type = "other"
    size = 0
    sha256 = None
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            buf = f.read()
        file_type = detect_file_type(buf)
        sha256 = sha256_bytes(buf)
    except Exception:
        pass

    return {
        "path": str(path.resolve()),
        "relative_path": relative_path,
        "name": path.name,
        "file_type": file_type,
        "status": "failed",
        "size": size,
        "sha256": sha256,
        "attempts": attempts,
        "error": str(error),
        "error_type": type(error).__name__,
        "risk": {
            "level": "error",
            "highlight": False,
            "color": None,
            "reasons": [],
        },
    }


def analyze_with_retries(
    path: Path, relative_path: str, config: "TriageConfig"
) -> tuple[dict[str, Any], int, Optional[BaseException]]:
    last_error: Optional[BaseException] = None
    attempts = config.retries + 1
    for attempt in range(1, attempts + 1):
        try:
            logger.info("analyzing %s (attempt %d/%d)", relative_path, attempt, attempts)
            sample = analyze_file(path, relative_path, config)
            sample["attempts"] = attempt
            return sample, attempt, None
        except Exception as e:
            last_error = e
            logger.error(
                "analysis failed for %s (attempt %d/%d): %s: %s",
                relative_path,
                attempt,
                attempts,
                type(e).__name__,
                e,
            )
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("%s", traceback.format_exc())
            if attempt < attempts and config.retry_delay > 0:
                time.sleep(config.retry_delay)

    assert last_error is not None
    return failure_record(path, relative_path, last_error, attempts), attempts, last_error


def configure_logging(log_path: Path, debug: bool, quiet: bool) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stderr)
    if quiet:
        console_handler.setLevel(logging.ERROR)
    elif debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def default_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


def collect_rule_files(paths: list[Path]) -> list[Path]:
    if not paths:
        return []
    return capa.rules.collect_rule_file_paths(paths)


def rules_signature(paths: list[Path]) -> str:
    files = collect_rule_files(paths)
    if not files:
        return "none"

    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.as_posix().encode("utf-8", errors="replace"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def load_rules(rule_paths: list[Path]) -> Optional[RuleSet]:
    for path in rule_paths:
        if not path.exists():
            raise MissingRulesError(f"rules path does not exist: {path}")

    if not collect_rule_files(rule_paths):
        logger.warning("no rule files found; triage will run without rule matching")
        return None

    try:
        return capa.rules.get_rules(rule_paths, enable_cache=False)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        raise TriageError(f"failed to load rules: {e}") from e


def analysis_signature(rules_sig: str, config: "TriageConfig") -> str:
    payload = {
        "schema": TRIAGE_SCHEMA_VERSION,
        "rules": rules_sig,
        "scope": "full" if config.deep else "file",
        "string_min_length": config.string_min_length,
        "max_strings": config.max_strings,
        "high_risk_namespaces": sorted(config.high_risk_namespaces),
        "high_risk_techniques": sorted(config.high_risk_techniques),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class TriageConfig:
    def __init__(
        self,
        ruleset: Optional[RuleSet],
        rules_paths: list[Path],
        string_min_length: int,
        max_strings: int,
        high_risk_namespaces: tuple[str, ...],
        high_risk_techniques: frozenset[str],
        retries: int,
        retry_delay: float,
        deep: bool = False,
    ):
        self.ruleset = ruleset
        self.rules_paths = rules_paths
        self.string_min_length = string_min_length
        self.max_strings = max_strings
        self.high_risk_namespaces = high_risk_namespaces
        self.high_risk_techniques = high_risk_techniques
        self.retries = retries
        self.retry_delay = retry_delay
        self.deep = deep
        self.rules_signature = rules_signature(rules_paths)
        self.analysis_signature = analysis_signature(self.rules_signature, self)


def load_state(path: Path, signature: str, source_dir: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning("failed to read incremental state %s, starting fresh: %s", path, e)
        return {}

    if data.get("schema_version") != STATE_SCHEMA_VERSION:
        logger.warning("incremental state has an unsupported schema, starting fresh")
        return {}

    if data.get("analysis_signature") != signature:
        logger.info("rules or triage options changed; reprocessing all files")
        return {}

    if data.get("source_dir") != str(source_dir.resolve()):
        logger.info("incremental state belongs to a different source directory; reprocessing all files")
        return {}

    entries = data.get("entries")
    if not isinstance(entries, dict):
        logger.warning("incremental state has an invalid entries table, starting fresh")
        return {}

    valid: dict[str, dict[str, Any]] = {}
    for relative_path, entry in entries.items():
        if not isinstance(relative_path, str) or not isinstance(entry, dict):
            continue
        if not isinstance(entry.get("fingerprint"), dict) or not isinstance(entry.get("sample"), dict):
            continue
        valid[relative_path] = entry
    return valid


def state_entry(fingerprint: dict[str, int], sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "sample": sample,
    }


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    Path(tmp_path).replace(path)


def write_text_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(data, encoding="utf-8")
    Path(tmp_path).replace(path)


def write_state(path: Path, signature: str, entries: dict[str, dict[str, Any]], source_dir: Path) -> None:
    data = {
        "schema_version": STATE_SCHEMA_VERSION,
        "analysis_signature": signature,
        "source_dir": str(source_dir.resolve()),
        "updated_at": utc_now(),
        "entries": entries,
    }
    write_json_atomic(path, data)


def collect_input_files(
    root: Path,
    recursive: bool,
    excluded_root: Path,
    excluded_files: set[Path],
) -> list[Path]:
    files: list[Path] = []
    excluded_files = {path.resolve() for path in excluded_files}
    skip_output_root = excluded_root.resolve() != root.resolve()

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            current = Path(dirpath)
            if skip_output_root:
                dirnames[:] = [name for name in dirnames if (current / name).resolve() != excluded_root.resolve()]
            for filename in filenames:
                path = current / filename
                if path.resolve() in excluded_files:
                    continue
                if path.is_file():
                    files.append(path)
    else:
        for path in root.iterdir():
            if path.resolve() in excluded_files:
                continue
            if path.is_file():
                files.append(path)

    return sorted(files, key=lambda path: path.relative_to(root).as_posix().lower())


def build_grouped_report(
    source_dir: Path,
    recursive: bool,
    config: "TriageConfig",
    samples: list[dict[str, Any]],
    stats: dict[str, Any],
    started_at: str,
) -> dict[str, Any]:
    group_names = ("pe", "elf", "other")
    groups: dict[str, dict[str, Any]] = {
        name: {
            "count": 0,
            "high_risk_count": 0,
            "failed_count": 0,
            "samples": [],
        }
        for name in group_names
    }

    for sample in samples:
        group_name = sample.get("file_type", "other")
        if group_name not in groups:
            group_name = "other"
        groups[group_name]["samples"].append(sample)

    for group in groups.values():
        group["samples"].sort(
            key=lambda sample: (
                sample.get("status") != "failed",
                sample.get("risk", {}).get("level") != "high",
                sample.get("relative_path", "").lower(),
            )
        )
        group["count"] = len(group["samples"])
        group["high_risk_count"] = sum(sample.get("risk", {}).get("level") == "high" for sample in group["samples"])
        group["failed_count"] = sum(sample.get("status") == "failed" for sample in group["samples"])

    failures = [sample for sample in samples if sample.get("status") == "failed"]
    risk_summary = {
        "high": sum(sample.get("risk", {}).get("level") == "high" for sample in samples),
        "clean": sum(
            sample.get("status") == "ok" and sample.get("risk", {}).get("level") != "high" for sample in samples
        ),
        "failed": len(failures),
    }

    return {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "started_at": started_at,
        "generated_at": utc_now(),
        "source": {
            "path": str(source_dir.resolve()),
            "recursive": recursive,
        },
        "run": stats,
        "rules": {
            "scope": "full" if config.deep else "file",
            "count": (
                len([rule for rule in config.ruleset.rules.values() if not rule.is_subscope_rule()])
                if config.ruleset is not None
                else 0
            ),
            "paths": [str(path) for path in config.rules_paths],
            "signature": config.rules_signature,
        },
        "risk_summary": risk_summary,
        "groups": groups,
        "failures": failures,
    }


def md_escape(value: Any) -> str:
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")
    return text


def md_code(value: Any) -> str:
    return f"`{md_escape(value)}`"


def md_risk_cell(sample: dict[str, Any]) -> str:
    if sample.get("status") == "failed":
        return "⚠️ FAILED"
    if sample.get("risk", {}).get("level") == "high":
        return '<span style="color:red"><strong>HIGH</strong></span> 🔴'
    return "—"


def md_sample_cell(sample: dict[str, Any]) -> str:
    cell = md_code(sample["relative_path"])
    if sample.get("risk", {}).get("level") == "high":
        return f'<span style="color:red">{cell}</span>'
    return cell


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def short_list(values: list[str], limit: int = 4) -> str:
    if not values:
        return "—"
    shown = [md_code(value) for value in values[:limit]]
    if len(values) > limit:
        shown.append(f"+{len(values) - limit}")
    return ", ".join(shown)


def render_markdown(report: dict[str, Any]) -> str:
    run = report["run"]
    rules = report["rules"]
    risk_summary = report["risk_summary"]
    group_labels = {"pe": "PE", "elf": "ELF", "other": "Other"}

    lines: list[str] = [
        "# capa batch triage summary",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Source: {md_code(report['source']['path'])}",
        f"Rule scope: {'full static' if rules['scope'] == 'full' else 'file-level'}; loaded rules: {rules['count']}",
        "",
        (
            "> Legend: "
            '<span style="color:red"><strong>HIGH</strong></span> 🔴 = high-risk rule match '
            "or suspicious import table; ⚠️ FAILED = analysis failed after retries."
        ),
        "",
        "## Run summary",
        "",
        "| Discovered | New/changed | Processed | Skipped | High risk | Clean | Failed |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        "| {discovered} | {new_or_changed} | {processed} | {skipped_unchanged} | {high} | {clean} | {failed} |".format(
            discovered=run["discovered"],
            new_or_changed=run["new_or_changed"],
            processed=run["processed"],
            skipped_unchanged=run["skipped_unchanged"],
            high=risk_summary["high"],
            clean=risk_summary["clean"],
            failed=risk_summary["failed"],
        ),
        "",
        "## Summary by file type",
        "",
        "| Type | Samples | High risk | Failed |",
        "|---|---:|---:|---:|",
    ]

    for group_name in ("pe", "elf", "other"):
        group = report["groups"][group_name]
        lines.append(
            f"| {group_labels[group_name]} | {group['count']} | {group['high_risk_count']} | {group['failed_count']} |"
        )

    high_risk_samples = [
        sample
        for group_name in ("pe", "elf", "other")
        for sample in report["groups"][group_name]["samples"]
        if sample.get("risk", {}).get("level") == "high"
    ]
    lines.extend(["", "## High-risk samples", ""])
    if not high_risk_samples:
        lines.append("No high-risk samples were identified.")
    else:
        for sample in high_risk_samples:
            lines.append(f"### {md_code(sample['relative_path'])}")
            lines.append("")
            lines.append(f"- Type: `{sample['file_type']}`; size: {format_bytes(sample['size'])}")
            if sample.get("sha256"):
                lines.append(f"- SHA256: {md_code(sample['sha256'])}")
            lines.append("- Reasons:")
            reasons = sample["risk"]["reasons"]
            for reason in reasons[:12]:
                lines.append(f"  - {md_escape(reason)}")
            if len(reasons) > 12:
                lines.append(f"  - +{len(reasons) - 12} more in triage.json")

            high_rules = [match["name"] for match in sample.get("rules", {}).get("matches", []) if match["high_risk"]]
            if high_rules:
                lines.append(f"- High-risk rules: {short_list(high_rules, limit=8)}")

            suspicious = sample.get("imports", {}).get("suspicious", [])
            if suspicious:
                rendered = [
                    f"{entry['module']}!{entry['name']} ({', '.join(entry['categories'])})" for entry in suspicious[:8]
                ]
                lines.append(f"- Suspicious imports: {short_list(rendered, limit=8)}")

            header = sample.get("header", {})
            arch = header.get("machine") or header.get("class")
            entry_point = header.get("entry_point_va") or header.get("entry_point")
            if arch or entry_point:
                lines.append(f"- Header: arch/machine={arch or '—'}, entry={entry_point or '—'}")

            string_items = sample.get("strings", {}).get("items", [])[:5]
            if string_items:
                values = [item["value"] for item in string_items]
                lines.append(f"- String samples: {short_list(values, limit=5)}")
            lines.append("")

    for group_name in ("pe", "elf", "other"):
        group = report["groups"][group_name]
        lines.extend(["", f"## {group_labels[group_name]} files ({group['count']})", ""])
        if not group["samples"]:
            lines.append("No files in this group.")
            continue

        lines.extend([
            "| Risk | Sample | Arch / type | Size | Rules | Suspicious imports |",
            "|---|---|---|---:|---:|---|",
        ])
        for sample in group["samples"]:
            if sample.get("status") == "failed":
                lines.append(
                    f"| {md_risk_cell(sample)} | {md_sample_cell(sample)} | `{sample['file_type']}` "
                    f"| {format_bytes(sample['size'])} | — | — |"
                )
                continue

            header = sample.get("header", {})
            arch = header.get("machine") or header.get("class") or sample["file_type"]
            rules_count = sample.get("rules", {}).get("matched_count", 0)
            suspicious = sample.get("imports", {}).get("suspicious", [])
            suspicious_names = [f"{entry['name']}" for entry in suspicious]
            lines.append(
                f"| {md_risk_cell(sample)} | {md_sample_cell(sample)} | {md_escape(arch)} "
                f"| {format_bytes(sample['size'])} | {rules_count} | "
                f"{short_list(suspicious_names, limit=3) if suspicious_names else '—'} |"
            )

    failures = report["failures"]
    lines.extend(["", "## Failures", ""])
    if not failures:
        lines.append("No analysis failures.")
    else:
        for sample in failures:
            lines.append(
                f"- {md_code(sample['relative_path'])} after {sample.get('attempts', 1)} attempt(s): "
                f"{md_escape(sample.get('error_type', 'Error'))}: {md_escape(sample.get('error', ''))}"
            )

    lines.append("")
    return "\n".join(lines)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capa triage",
        description="Batch triage PE/ELF files in a directory and write JSON + Markdown reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  triage a directory recursively with the embedded rules
    capa triage samples/ -o triage-out

  use a custom rule set and four retries
    capa triage samples/ -r ./capa-rules -r ./local-rules --retries 4 -o triage-out

  run function-scope rules too (slower)
    capa triage samples/ -r ./capa-rules --deep -o triage-out

  only scan the top-level directory and reprocess unchanged files
    capa triage samples/ --no-recursive --force -o triage-out

outputs:
  triage.json          normalized machine-readable results
  triage.md            Markdown summary with red HIGH markers
  triage.log           per-file progress, retries, and failures
  .capa-triage-state.json  incremental state
""",
    )
    parser.add_argument("input_dir", type=Path, help="directory containing samples")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("triage-output"),
        help="directory for triage.json, triage.md, log, and state (default: triage-output)",
    )
    parser.add_argument(
        "-r",
        "--rules",
        type=Path,
        action="append",
        default=[],
        help="rule file or directory; may be repeated (default: embedded rules)",
    )
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="skip rule matching and only collect headers, imports, and strings",
    )
    parser.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="recurse into subdirectories (default: true)",
    )
    parser.add_argument(
        "--retries",
        type=nonnegative_int,
        default=2,
        help="retry count after the first failure, per file (default: 2)",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=0.2,
        help="seconds to wait between retries (default: 0.2)",
    )
    parser.add_argument(
        "--string-min-length",
        type=positive_int,
        default=4,
        help="minimum extracted string length (default: 4)",
    )
    parser.add_argument(
        "--max-strings",
        type=nonnegative_int,
        default=250,
        help="maximum strings stored per sample; 0 means unlimited (default: 250)",
    )
    parser.add_argument(
        "--state",
        type=Path,
        help="incremental state path (default: OUTPUT_DIR/.capa-triage-state.json)",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help="log path (default: OUTPUT_DIR/triage.log)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="reprocess all files even when unchanged",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="run full function/instruction-scope rule matching with vivisect (slower)",
    )
    parser.add_argument(
        "--high-risk-namespace",
        action="append",
        default=[],
        help="additional high-risk rule namespace prefix; may be repeated",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="return exit code 1 if any file fails analysis",
    )
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress on stderr")
    return parser


def resolve_rule_paths(args: argparse.Namespace) -> list[Path]:
    if args.no_rules and args.rules:
        raise TriageError("--no-rules cannot be combined with --rules")
    if args.no_rules:
        return []
    if args.rules:
        return [path.expanduser() for path in args.rules]

    embedded = default_rules_path().expanduser()
    if embedded.exists() and collect_rule_files([embedded]):
        return [embedded]

    logger.warning(
        "embedded rules not found at %s; proceeding without rule matching "
        "(use -r/--rules to provide a capa rule directory)",
        embedded,
    )
    return []


def print_report_paths(output_dir: Path, json_path: Path, markdown_path: Path, log_path: Path, quiet: bool) -> None:
    if quiet:
        return
    print(f"Triage reports written to {output_dir}")
    print(f"  JSON:     {json_path}")
    print(f"  Markdown: {markdown_path}")
    print(f"  Log:      {log_path}")


def main(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    args = parser.parse_args(argv)

    source_dir = args.input_dir.expanduser()
    if not source_dir.exists():
        print(f"error: input directory does not exist: {source_dir}", file=sys.stderr)
        return E_MISSING_FILE
    if not source_dir.is_dir():
        print(f"error: input path is not a directory: {source_dir}", file=sys.stderr)
        return E_MISSING_FILE

    output_dir = args.output_dir.expanduser()
    json_path = output_dir / "triage.json"
    markdown_path = output_dir / "triage.md"
    log_path = args.log.expanduser() if args.log else output_dir / "triage.log"
    state_path = args.state.expanduser() if args.state else output_dir / ".capa-triage-state.json"

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        if args.log:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        if args.state:
            state_path.parent.mkdir(parents=True, exist_ok=True)
        configure_logging(log_path, args.debug, args.quiet)
    except OSError as e:
        print(f"error: failed to prepare output directory: {e}", file=sys.stderr)
        return 1

    started_at = utc_now()
    logger.info("triage started: source=%s output=%s", source_dir, output_dir)

    try:
        rule_paths = resolve_rule_paths(args)
        ruleset = load_rules(rule_paths)
        namespaces = tuple(DEFAULT_HIGH_RISK_NAMESPACES) + tuple(
            prefix if prefix.endswith("/") else f"{prefix}/" for prefix in args.high_risk_namespace
        )
        config = TriageConfig(
            ruleset=ruleset,
            rules_paths=rule_paths,
            string_min_length=args.string_min_length,
            max_strings=args.max_strings,
            high_risk_namespaces=tuple(dict.fromkeys(namespaces)),
            high_risk_techniques=DEFAULT_HIGH_RISK_TECHNIQUES,
            retries=args.retries,
            retry_delay=max(0.0, args.retry_delay),
            deep=args.deep,
        )

        files = collect_input_files(
            source_dir,
            recursive=args.recursive,
            excluded_root=output_dir,
            excluded_files={json_path, markdown_path, log_path, state_path},
        )
        logger.info("discovered %d input file(s)", len(files))

        previous_entries = load_state(state_path, config.analysis_signature, source_dir)
        entries: dict[str, dict[str, Any]] = {}
        samples: list[dict[str, Any]] = []
        new_or_changed = 0
        skipped = 0
        succeeded = 0
        failed = 0
        retries_used = 0

        current_keys = {path.relative_to(source_dir).as_posix() for path in files}
        for key in list(previous_entries):
            if key not in current_keys:
                del previous_entries[key]

        for path in files:
            relative_path = path.relative_to(source_dir).as_posix()
            try:
                fingerprint = file_fingerprint(path)
            except OSError as e:
                logger.error("failed to stat %s: %s", relative_path, e)
                samples.append(failure_record(path, relative_path, e, 0))
                failed += 1
                continue

            previous = previous_entries.get(relative_path)
            if (
                not args.force
                and previous is not None
                and previous.get("fingerprint") == fingerprint
                and previous.get("sample", {}).get("status") == "ok"
            ):
                logger.info("skipping unchanged %s", relative_path)
                samples.append(previous["sample"])
                entries[relative_path] = previous
                skipped += 1
                continue

            new_or_changed += 1
            sample, attempts, error = analyze_with_retries(path, relative_path, config)
            samples.append(sample)
            retries_used += max(0, attempts - 1)

            if error is None and sample.get("status") == "ok":
                succeeded += 1
                try:
                    fingerprint = file_fingerprint(path)
                    entries[relative_path] = state_entry(fingerprint, sample)
                except OSError as e:
                    logger.warning("failed to update state for %s: %s", relative_path, e)
            else:
                failed += 1

        stats = {
            "discovered": len(files),
            "new_or_changed": new_or_changed,
            "processed": new_or_changed,
            "skipped_unchanged": skipped,
            "succeeded": succeeded,
            "failed": failed,
            "retries": retries_used,
        }
        report = build_grouped_report(
            source_dir=source_dir,
            recursive=args.recursive,
            config=config,
            samples=samples,
            stats=stats,
            started_at=started_at,
        )

        write_json_atomic(json_path, report)
        write_text_atomic(markdown_path, render_markdown(report))
        write_state(state_path, config.analysis_signature, entries, source_dir)

        logger.info(
            "triage complete: discovered=%d new_or_changed=%d skipped=%d high_risk=%d failed=%d retries=%d",
            stats["discovered"],
            stats["new_or_changed"],
            stats["skipped_unchanged"],
            report["risk_summary"]["high"],
            stats["failed"],
            stats["retries"],
        )
        print_report_paths(output_dir, json_path, markdown_path, log_path, args.quiet)
        if not args.quiet:
            print(
                "Summary: "
                f"{report['risk_summary']['high']} high risk, "
                f"{report['risk_summary']['clean']} clean, "
                f"{report['risk_summary']['failed']} failed"
            )

        if args.fail_on_error and failed:
            return 1
        return 0
    except MissingRulesError as e:
        logger.error("%s", e)
        return E_MISSING_RULES
    except (TriageError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", e)
        return E_INVALID_RULE
    except KeyboardInterrupt:
        logger.error("triage interrupted")
        return 130
    except Exception as e:
        logger.exception("unexpected triage failure: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
