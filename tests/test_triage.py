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

import json
import struct
from pathlib import Path

import capa.main
import capa.triage

HIGH_RISK_RULE = """
rule:
  meta:
    name: triage high risk test
    namespace: impact/test
    severity: high
    scopes:
      static: file
      dynamic: file
  features:
    - substring: "high risk marker"
"""


def write_minimal_pe(path: Path, marker: bytes) -> None:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    buf[0x84 : 0x84 + 20] = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)

    optional = bytearray(0xF0)
    struct.pack_into(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        optional,
        0,
        0x20B,
        14,
        0,
        0,
        0,
        0,
        0x1000,
        0x1000,
        0x140000000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    buf[0x84 + 20 : 0x84 + 20 + 0xF0] = optional

    section_offset = 0x84 + 20 + 0xF0
    buf[section_offset : section_offset + 40] = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    buf[0x200 : 0x200 + len(marker)] = marker
    path.write_bytes(bytes(buf))


def write_minimal_elf(path: Path) -> None:
    buf = bytearray(64)
    buf[0:16] = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        buf,
        16,
        2,
        62,
        1,
        0x1000,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        0,
        0,
    )
    path.write_bytes(bytes(buf))


def test_triage_dispatch_pe_elf_grouping_and_markdown(tmp_path: Path):
    samples = tmp_path / "samples"
    rules = tmp_path / "rules"
    output = tmp_path / "out"
    samples.mkdir()
    rules.mkdir()
    (rules / "high.yml").write_text(HIGH_RISK_RULE, encoding="utf-8")

    write_minimal_pe(samples / "sample.exe", b"high risk marker\x00")
    write_minimal_elf(samples / "sample.elf")

    assert (
        capa.main.main([
            "triage",
            str(samples),
            "-r",
            str(rules),
            "-o",
            str(output),
            "--retries",
            "0",
            "--quiet",
        ])
        == 0
    )

    report = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert report["groups"]["pe"]["count"] == 1
    assert report["groups"]["elf"]["count"] == 1
    assert report["risk_summary"]["high"] == 1

    pe_sample = report["groups"]["pe"]["samples"][0]
    assert pe_sample["header"]["machine"] == "IMAGE_FILE_MACHINE_AMD64"
    assert pe_sample["header"]["entry_point_va"] == "0x140001000"
    assert pe_sample["risk"]["highlight"] is True
    assert pe_sample["risk"]["color"] == "red"
    assert pe_sample["rules"]["matches"][0]["name"] == "triage high risk test"

    elf_sample = report["groups"]["elf"]["samples"][0]
    assert elf_sample["header"]["class"] == "ELFCLASS64"
    assert elf_sample["header"]["machine"] == "EM_X86_64"

    markdown = (output / "triage.md").read_text(encoding="utf-8")
    assert '<span style="color:red"><strong>HIGH</strong></span>' in markdown
    assert "triage high risk test" in markdown


def test_triage_incremental_keeps_cumulative_results(tmp_path: Path):
    samples = tmp_path / "samples"
    output = tmp_path / "out"
    samples.mkdir()
    (samples / "one.txt").write_text("one", encoding="utf-8")

    args = [
        str(samples),
        "-o",
        str(output),
        "--no-rules",
        "--retries",
        "0",
        "--quiet",
    ]
    assert capa.triage.main(args) == 0
    first = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert first["run"]["new_or_changed"] == 1

    assert capa.triage.main(args) == 0
    second = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert second["run"]["new_or_changed"] == 0
    assert second["run"]["skipped_unchanged"] == 1
    assert second["groups"]["other"]["count"] == 1

    (samples / "two.txt").write_text("two", encoding="utf-8")
    assert capa.triage.main(args) == 0
    third = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert third["run"]["new_or_changed"] == 1
    assert third["run"]["skipped_unchanged"] == 1
    assert third["groups"]["other"]["count"] == 2
    assert {sample["relative_path"] for sample in third["groups"]["other"]["samples"]} == {
        "one.txt",
        "two.txt",
    }


def test_triage_retries_transient_failure(tmp_path: Path, monkeypatch):
    samples = tmp_path / "samples"
    output = tmp_path / "out"
    samples.mkdir()
    (samples / "sample.txt").write_text("retry me", encoding="utf-8")

    original_analyze_file = capa.triage.analyze_file
    calls = 0

    def flaky_analyze_file(path, relative_path, config):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient parse failure")
        return original_analyze_file(path, relative_path, config)

    monkeypatch.setattr(capa.triage, "analyze_file", flaky_analyze_file)
    assert (
        capa.triage.main([
            str(samples),
            "-o",
            str(output),
            "--no-rules",
            "--retries",
            "1",
            "--retry-delay",
            "0",
            "--quiet",
        ])
        == 0
    )

    report = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert calls == 2
    assert report["run"]["retries"] == 1
    assert report["run"]["failed"] == 0
    assert report["groups"]["other"]["samples"][0]["attempts"] == 2


def test_triage_deep_mode_wiring(tmp_path: Path, monkeypatch):
    samples = tmp_path / "samples"
    rules = tmp_path / "rules"
    output = tmp_path / "out"
    samples.mkdir()
    rules.mkdir()
    (rules / "high.yml").write_text(HIGH_RISK_RULE, encoding="utf-8")
    write_minimal_pe(samples / "sample.exe", b"deep mode\x00")

    monkeypatch.setattr(capa.triage, "match_deep_rules", lambda path, file_type, config: {})
    assert (
        capa.triage.main([
            str(samples),
            "-r",
            str(rules),
            "-o",
            str(output),
            "--deep",
            "--retries",
            "0",
            "--quiet",
        ])
        == 0
    )

    report = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert report["rules"]["scope"] == "full"
    assert report["groups"]["pe"]["samples"][0]["rules"]["scope"] == "full"


def test_triage_failure_is_reported_and_logged(tmp_path: Path, monkeypatch):
    samples = tmp_path / "samples"
    output = tmp_path / "out"
    samples.mkdir()
    (samples / "sample.txt").write_text("always fail", encoding="utf-8")

    def broken_analyze_file(path, relative_path, config):
        raise ValueError("broken sample")

    monkeypatch.setattr(capa.triage, "analyze_file", broken_analyze_file)
    assert (
        capa.triage.main([
            str(samples),
            "-o",
            str(output),
            "--no-rules",
            "--retries",
            "1",
            "--retry-delay",
            "0",
            "--fail-on-error",
            "--quiet",
        ])
        == 1
    )

    report = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert report["run"]["failed"] == 1
    assert report["failures"][0]["attempts"] == 2
    assert report["failures"][0]["error_type"] == "ValueError"

    log = (output / "triage.log").read_text(encoding="utf-8")
    assert "attempt 2/2" in log
    assert "broken sample" in log


def test_suspicious_import_normalization():
    assert capa.triage.suspicious_import_categories("__imp_CreateRemoteThread@16") == ("process injection",)
    assert capa.triage.suspicious_import_categories("kernel32!VirtualAllocEx") == ("process injection",)
    assert capa.triage.suspicious_import_categories("GetProcAddress") == ()
