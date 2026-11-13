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

import abc
import logging
import threading
import concurrent.futures
from typing import Any, Callable, Iterator, Optional

from capa.features.common import Feature
from capa.features.address import Address
from capa.features.extractors.base_extractor import SampleHashes, StaticFeatureExtractor

logger = logging.getLogger(__name__)

# a file-scope handler extracts features from a parsed file.
# it receives the extractor's handler context as keyword arguments,
# e.g. pe=..., elf=..., buf=..., and yields (feature, address) pairs.
FileHandler = Callable[..., Iterator[tuple[Feature, Address]]]

# recognized error policies:
#  - "skip": log the failure and continue with the next handler (default)
#  - "raise": propagate the first failure to the caller
ON_ERROR_SKIP = "skip"
ON_ERROR_RAISE = "raise"


class ExtractionCancelledError(Exception):
    """raised when extraction is aborted via the extractor's cancellation event."""


class FileFeatureExtractor(StaticFeatureExtractor):
    """
    FileFeatureExtractor defines the interface for extractors that only
    support file-scope (and global-scope) features, such as the PE, ELF,
    and .NET file extractors.

    Subclasses provide:
      - get_handler_context(): the keyword arguments passed to every handler
      - get_file_handlers(): the ordered tuple of file-scope handlers
      - get_global_handlers(): the ordered tuple of global-scope handlers

    This base class uniformly applies the extraction policy to every handler:
      - timeout: per-handler wall-clock limit, in seconds (None disables the limit).
        a handler that exceeds the limit is logged and skipped.
        note: the timed-out handler keeps running in a daemon thread in the
        background, since Python threads cannot be killed; its results are discarded.
      - on_error: "skip" logs a handler failure and continues with the next
        handler; "raise" propagates the first failure to the caller.
      - cancellation: pass a threading.Event as cancel_event; when the event is
        set, extraction raises ExtractionCancelledError. cancellation is checked
        between handlers and between yielded features.

    Handlers are always invoked in the order given by get_file_handlers() /
    get_global_handlers(), and features are yielded in handler order, so the
    output of a subclass is deterministic.
    """

    def __init__(
        self,
        hashes: SampleHashes,
        *,
        timeout: Optional[float] = None,
        cancel_event: Optional[threading.Event] = None,
        on_error: str = ON_ERROR_SKIP,
    ):
        super().__init__(hashes)
        if on_error not in (ON_ERROR_SKIP, ON_ERROR_RAISE):
            raise ValueError(f"invalid on_error policy: {on_error!r}")
        self.timeout = timeout
        self.cancel_event = cancel_event
        self.on_error = on_error

    @abc.abstractmethod
    def get_handler_context(self) -> dict[str, Any]:
        """
        fetch the keyword arguments passed to every file/global handler,
        such as the parsed file object and the raw sample bytes.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_file_handlers(self) -> tuple[FileHandler, ...]:
        """
        fetch the ordered tuple of file-scope handlers.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_global_handlers(self) -> tuple[FileHandler, ...]:
        """
        fetch the ordered tuple of global-scope handlers.
        """
        raise NotImplementedError()

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from self._run_handlers(self.get_file_handlers())

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from self._run_handlers(self.get_global_handlers())

    def _check_cancelled(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ExtractionCancelledError(f"{type(self).__name__}: extraction cancelled")

    def _run_handlers(self, handlers: tuple[FileHandler, ...]) -> Iterator[tuple[Feature, Address]]:
        ctx = self.get_handler_context()
        for handler in handlers:
            self._check_cancelled()
            try:
                features = self._run_handler(handler, ctx)
            except ExtractionCancelledError:
                raise
            except Exception as e:
                if self.on_error == ON_ERROR_RAISE:
                    raise
                logger.warning("handler %s failed: %s", handler.__name__, e)
                continue
            for feature, address in features:
                self._check_cancelled()
                yield feature, address

    def _run_handler(self, handler: FileHandler, ctx: dict[str, Any]) -> list[tuple[Feature, Address]]:
        if self.timeout is None:
            return list(handler(**ctx))

        # run the handler in a worker thread so we can bound its wall-clock time.
        # a timed-out thread is left running in the background (Python threads
        # cannot be killed), but its results are discarded.
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(lambda: list(handler(**ctx)))
        try:
            return future.result(timeout=self.timeout)
        except concurrent.futures.TimeoutError:
            logger.warning("handler %s timed out after %.1fs", handler.__name__, self.timeout)
            return []
        finally:
            pool.shutdown(wait=False)

    #
    # file-scope-only extractors do not support function/basic block/instruction scopes.
    #

    def get_functions(self):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def extract_function_features(self, fh):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def get_basic_blocks(self, fh):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def extract_basic_block_features(self, fh, bbh):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def get_instructions(self, fh, bbh):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def extract_insn_features(self, fh, bbh, ih):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def is_library_function(self, addr):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")

    def get_function_name(self, addr):
        raise NotImplementedError(f"{type(self).__name__} can only be used to extract file features")
