# Copyright 2024 Google LLC
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

import time
import struct
import threading

import pytest

from capa.features.common import OS, FORMAT_PE, OS_WINDOWS, Arch, Format, Characteristic
from capa.features.address import NO_ADDRESS
from capa.features.extractors.base_extractor import SampleHashes
from capa.features.extractors.file_extractor import (
    FileFeatureExtractor,
    ExtractionCancelledError,
)

HASHES = SampleHashes(md5="00" * 16, sha1="00" * 20, sha256="00" * 32)


def handler_format_pe(**kwargs):
    yield Format(FORMAT_PE), NO_ADDRESS


def handler_os_windows(**kwargs):
    yield OS(OS_WINDOWS), NO_ADDRESS


def handler_arch(**kwargs):
    yield Arch("i386"), NO_ADDRESS


def handler_boom(**kwargs):
    raise RuntimeError("handler exploded")
    yield  # pragma: no cover


def handler_slow(**kwargs):
    time.sleep(2)
    yield Characteristic("slow"), NO_ADDRESS


class DummyFileExtractor(FileFeatureExtractor):
    def __init__(self, file_handlers=(), global_handlers=(), **kwargs):
        super().__init__(hashes=HASHES, **kwargs)
        self._file_handlers = tuple(file_handlers)
        self._global_handlers = tuple(global_handlers)

    def get_base_address(self):
        return NO_ADDRESS

    def get_handler_context(self):
        return {}

    def get_file_handlers(self):
        return self._file_handlers

    def get_global_handlers(self):
        return self._global_handlers


def test_handlers_run_in_order():
    extractor = DummyFileExtractor(file_handlers=[handler_format_pe, handler_os_windows, handler_arch])
    features = [f for f, _ in extractor.extract_file_features()]
    assert features == [Format(FORMAT_PE), OS(OS_WINDOWS), Arch("i386")]


def test_global_handlers_run_in_order():
    extractor = DummyFileExtractor(global_handlers=[handler_os_windows, handler_arch])
    features = [f for f, _ in extractor.extract_global_features()]
    assert features == [OS(OS_WINDOWS), Arch("i386")]


def test_handler_failure_is_skipped_by_default(caplog):
    extractor = DummyFileExtractor(file_handlers=[handler_format_pe, handler_boom, handler_os_windows])
    features = [f for f, _ in extractor.extract_file_features()]
    assert features == [Format(FORMAT_PE), OS(OS_WINDOWS)]
    assert "handler_boom" in caplog.text


def test_handler_failure_raise_policy():
    extractor = DummyFileExtractor(file_handlers=[handler_format_pe, handler_boom], on_error="raise")
    with pytest.raises(RuntimeError, match="handler exploded"):
        list(extractor.extract_file_features())


def test_invalid_on_error_policy():
    with pytest.raises(ValueError):
        DummyFileExtractor(on_error="explode")


def test_handler_timeout_is_skipped(caplog):
    extractor = DummyFileExtractor(file_handlers=[handler_slow, handler_os_windows], timeout=0.1)
    features = [f for f, _ in extractor.extract_file_features()]
    # the slow handler times out and is skipped; the next handler still runs.
    assert features == [OS(OS_WINDOWS)]
    assert "handler_slow" in caplog.text
    assert "timed out" in caplog.text


def test_cancellation_before_start():
    cancel_event = threading.Event()
    cancel_event.set()
    extractor = DummyFileExtractor(file_handlers=[handler_format_pe], cancel_event=cancel_event)
    with pytest.raises(ExtractionCancelledError):
        list(extractor.extract_file_features())


def test_cancellation_stops_remaining_handlers():
    cancel_event = threading.Event()

    def handler_cancelling(**kwargs):
        cancel_event.set()
        yield Format(FORMAT_PE), NO_ADDRESS

    extractor = DummyFileExtractor(
        file_handlers=[handler_cancelling, handler_os_windows],
        cancel_event=cancel_event,
    )
    with pytest.raises(ExtractionCancelledError):
        list(extractor.extract_file_features())


def test_file_scope_only_methods_raise():
    extractor = DummyFileExtractor()
    with pytest.raises(NotImplementedError):
        extractor.get_functions()
    with pytest.raises(NotImplementedError):
        extractor.get_basic_blocks(None)
    with pytest.raises(NotImplementedError):
        extractor.get_instructions(None, None)


#
# parity tests: the wired-in PE/ELF extractors must produce exactly the same
# features, in the same order, as the underlying module-level handlers.
#

MINIMAL_ELF = (
    b"\x7fELF"
    + bytes([2, 1, 1, 0])
    + b"\x00" * 8
    + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
)


def make_minimal_pe() -> bytes:
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    file_header = struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)  # Magic: PE32
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 56, 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", opt, 68, 3)  # Subsystem
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    return dos + b"PE\x00\x00" + file_header + bytes(opt)


def test_pefile_extractor_matches_module_handlers(tmp_path):
    pefile = pytest.importorskip("pefile")
    import capa.features.extractors.pefile as pefile_extractor

    buf = make_minimal_pe()
    path = tmp_path / "sample.exe"
    path.write_bytes(buf)

    extractor = pefile_extractor.PefileFeatureExtractor(path)
    pe = pefile.PE(data=buf)

    assert list(extractor.extract_file_features()) == list(pefile_extractor.extract_file_features(pe, buf))
    assert list(extractor.extract_global_features()) == list(pefile_extractor.extract_global_features(pe, buf))


def test_pefile_extractor_accepts_policy_kwargs(tmp_path):
    import capa.features.extractors.pefile as pefile_extractor

    path = tmp_path / "sample.exe"
    path.write_bytes(make_minimal_pe())

    cancel_event = threading.Event()
    extractor = pefile_extractor.PefileFeatureExtractor(path, timeout=5.0, cancel_event=cancel_event)
    assert extractor.timeout == 5.0
    assert extractor.cancel_event is cancel_event
    assert extractor.on_error == "skip"

    cancel_event.set()
    with pytest.raises(ExtractionCancelledError):
        list(extractor.extract_file_features())


def test_elffile_extractor_matches_module_handlers(tmp_path):
    pytest.importorskip("elftools")
    import io

    from elftools.elf.elffile import ELFFile

    import capa.features.extractors.elffile as elffile_extractor

    path = tmp_path / "sample.elf"
    path.write_bytes(MINIMAL_ELF)

    extractor = elffile_extractor.ElfFeatureExtractor(path)
    elf = ELFFile(io.BytesIO(MINIMAL_ELF))

    assert list(extractor.extract_file_features()) == list(elffile_extractor.extract_file_features(elf, MINIMAL_ELF))
    assert list(extractor.extract_global_features()) == list(
        elffile_extractor.extract_global_features(elf, MINIMAL_ELF)
    )


def test_format_extractors_use_unified_base():
    import capa.features.extractors.pefile as pefile_extractor
    import capa.features.extractors.elffile as elffile_extractor
    import capa.features.extractors.dotnetfile as dotnetfile_extractor

    assert issubclass(pefile_extractor.PefileFeatureExtractor, FileFeatureExtractor)
    assert issubclass(elffile_extractor.ElfFeatureExtractor, FileFeatureExtractor)
    assert issubclass(dotnetfile_extractor.DotnetFileFeatureExtractor, FileFeatureExtractor)

    # handlers are wired to the module-level handler tuples, preserving order.
    pe_extractor = pefile_extractor.PefileFeatureExtractor.__new__(pefile_extractor.PefileFeatureExtractor)
    assert pe_extractor.get_file_handlers() == pefile_extractor.FILE_HANDLERS
    assert pe_extractor.get_global_handlers() == pefile_extractor.GLOBAL_HANDLERS

    elf_extractor = elffile_extractor.ElfFeatureExtractor.__new__(elffile_extractor.ElfFeatureExtractor)
    assert elf_extractor.get_file_handlers() == elffile_extractor.FILE_HANDLERS
    assert elf_extractor.get_global_handlers() == elffile_extractor.GLOBAL_HANDLERS

    dotnet_extractor = dotnetfile_extractor.DotnetFileFeatureExtractor.__new__(
        dotnetfile_extractor.DotnetFileFeatureExtractor
    )
    assert dotnet_extractor.get_file_handlers() == dotnetfile_extractor.FILE_HANDLERS
    assert dotnet_extractor.get_global_handlers() == dotnetfile_extractor.GLOBAL_HANDLERS
