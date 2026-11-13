# Developing a file-format feature extractor

capa extracts features from samples through *feature extractor* backends.
Extractors that only support file-scope (and global-scope) features — such as
the PE (`pefile`), ELF (`elffile`), and .NET (`dotnetfile`) extractors — share a
common base class, `FileFeatureExtractor`, defined in
`capa/features/extractors/file_extractor.py`. The base class standardizes how
handlers are dispatched and how timeouts, errors, and cancellation are handled,
so new formats only need to provide the parsing logic.

## Writing a new extractor

A file-format extractor consists of:

1. **Handlers**: generator functions that yield `(Feature, Address)` pairs.
   Each handler receives the extractor's *handler context* as keyword arguments
   (conventionally the parsed file object and the raw sample bytes) and should
   accept `**kwargs` so the context can grow without breaking existing handlers.

   ```python
   def extract_file_format(**kwargs):
       yield Format(FORMAT_PE), NO_ADDRESS

   def extract_file_section_names(pe, **kwargs):
       for section in pe.sections:
           yield Section(section.name), AbsoluteVirtualAddress(section.address)
   ```

2. **Ordered handler tuples**: `FILE_HANDLERS` and `GLOBAL_HANDLERS`. Handlers
   run in tuple order and features are yielded in that order, so the output of
   an extractor is deterministic. Do not reorder existing tuples — the output
   order is part of capa's observable behavior.

3. **The extractor class**: subclass `FileFeatureExtractor` and implement
   `get_handler_context()`, `get_file_handlers()`, `get_global_handlers()`, and
   `get_base_address()`.

   ```python
   class MyFormatFeatureExtractor(FileFeatureExtractor):
       def __init__(self, path: Path, **kwargs):
           super().__init__(hashes=SampleHashes.from_bytes(path.read_bytes()), **kwargs)
           self.path = path
           self.parsed = parse_my_format(path)

       def get_base_address(self):
           return AbsoluteVirtualAddress(self.parsed.image_base)

       def get_handler_context(self):
           return {"pe": self.parsed, "buf": self.path.read_bytes()}

       def get_file_handlers(self):
           return FILE_HANDLERS

       def get_global_handlers(self):
           return GLOBAL_HANDLERS
   ```

`FileFeatureExtractor` implements `extract_file_features()` and
`extract_global_features()` for you, and raises `NotImplementedError` for all
function/basic-block/instruction-scope methods.

## Extraction policy: timeouts, errors, cancellation

The base class applies a uniform policy to every handler. The policy is
configured via constructor keyword arguments:

- `timeout: float | None` — per-handler wall-clock limit in seconds. A handler
  that exceeds the limit is logged and skipped, and extraction continues with
  the next handler. `None` (the default) disables the limit. Note: a timed-out
  handler keeps running in a background thread (Python threads cannot be
  killed), but its results are discarded.
- `on_error: "skip" | "raise"` — with `"skip"` (the default), a handler that
  raises an exception is logged and skipped, and extraction continues with the
  next handler. With `"raise"`, the first failure propagates to the caller.
- `cancel_event: threading.Event | None` — when the event is set, extraction
  aborts by raising `ExtractionCancelledError`. Cancellation is checked between
  handlers and between yielded features.

Example:

```python
import threading

cancel = threading.Event()
extractor = MyFormatFeatureExtractor(path, timeout=30.0, cancel_event=cancel)
try:
    for feature, address in extractor.extract_file_features():
        ...
except ExtractionCancelledError:
    ...
```

Because the policy lives in the base class, all file-format extractors behave
identically: a slow or corrupt file degrades extraction to the handlers that
succeed, in a deterministic order, instead of crashing the whole analysis.

## Tests

See `tests/test_file_extractor.py` for examples covering handler ordering,
timeouts, extraction failures, and cancellation. Parity between an extractor
class and its module-level handlers can be tested with small crafted buffers,
without requiring real malware samples.
