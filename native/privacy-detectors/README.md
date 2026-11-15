# External privacy detectors

Register a local detector in `privacy-models.json` in the same local directory
as Magpie's `settings.json`. Restart Magpie to load the file, then select the
detector under Settings → Privacy → Find with a local model. Turn on masking
for secrets or personal data and enable local model detection.

```json
{
  "externalPrivacyModels": [
    {
      "id": "s0r",
      "name": "S0R",
      "command": "/absolute/path/to/python",
      "args": ["/absolute/path/to/s0r.py", "--model", "/absolute/path/to/s0r/model"],
      "revision": "0.1.0"
    }
  ]
}
```

Use a Python environment with the private S0R release's `s0r_router` and its
dependencies installed. Point to the release's original `model/` directory.
The S0R adapter disables the release's own rules and returns model findings
only. Magpie uses its existing rules, privacy actions and reply restoration.

The command must be an absolute path. Magpie executes it directly with the
given arguments. It sends original request text over a local pipe. Only
configure trusted executables. The file is local to the current Magpie
profile. IDs use lowercase letters, digits, underscores or hyphens, must
start with a letter or digit, and appear internally as `external/<id>`.
`minScore` optionally adds a Magpie-side minimum score. The default of zero
accepts the detector's own cutoff. Set a new `revision` if replacing weights
or detector code in place so Magpie refreshes its cached results.

An adapter implements the [pf-serve pipe protocol](../privacy-filter/pf-serve.cpp)
over standard input and output. The ready line is JSON. Requests and responses
are little-endian binary after that. Each finding has a UTF-8 byte range, a
score between zero and one, and a [Magpie model label](../../internal/redact/model.go).
Log startup diagnostics to stderr. Magpie starts and reuses the process and
stops it when switched off or idle. The detector executable and weights belong
to the user.
