# Admin Guide: Adding a New Scanning Tool

## Table of Contents

1. [Overview — How Tools Work](#overview)
2. [Step 1 — Create the Tool Definition JSON](#step-1)
3. [Step 2 — Register the Tool via API](#step-2)
4. [Step 3 — Verify Registration](#step-3)
5. [Complete JSON Reference](#reference)
6. [Output Class Decision Tree](#output-class)
7. [SSE Display Formatting](#sse-display)
8. [Pipeline Chaining](#pipeline)
9. [Common Mistakes Checklist](#checklist)
10. [Real Examples](#examples)

---

## Overview — How Tools Work <a name="overview"></a>

Each tool is stored as a row in the `tools` database table. The Go backend reads this at scan time — **no code changes** are ever needed to add a new tool. The entire behaviour (how the tool runs, how its output is parsed, how results are displayed, how it chains with other tools) is driven by the JSON metadata you define.

```
tool.json (you write this)
      │
      ▼
POST /api/tool (CreateTool gRPC → FastAPI)
      │
      ▼
tools table in Postgres
      │
      ▼  at scan time:
      ├── shadow_output_config  → decides streaming vs file capture
      ├── input_schema          → builds CLI flags for the container
      ├── output_schema         → drives SSE display + DB parsing + pipeline input
      ├── scan_config           → exposes user-facing options
      ├── parser_config         → maps JSON/XML fields → findings
      └── denied_options        → security: blocks dangerous flags
```

---

## Step 1 — Create the Tool Definition JSON <a name="step-1"></a>

Create a file `<toolname>.json` in the **backend root** (`auto-offensive-backend/`).

Use the template below and fill in every section. The sections are explained in [Complete JSON Reference](#reference).

```json
{
  "category_name": "Reconnaissance",
  "tool_name": "mytool",
  "tool_description": "One-line description shown in UI",
  "tool_long_description": "Paragraph shown in tool detail page.",
  "examples": [
    { "target": "example.com" }
  ],
  "input_schema": { ... },
  "output_schema": { ... },
  "scan_config": { ... },
  "install_method": "docker",
  "version": "1.0.0",
  "image_ref": "vendor/mytool:v1.0.0",
  "image_source": "dockerhub",
  "is_active": true,
  "denied_options": [],
  "shadow_output_config": { ... },
  "parser_config": { ... }
}
```

---

## Step 2 — Register the Tool via API <a name="step-2"></a>

Tools are registered through the **FastAPI gateway's Tool API** (backed by the Go gRPC `ToolService`).

### Option A — cURL (recommended for scripting)

```bash
# Set your API base URL
API=http://localhost:8000

# Read the JSON file and POST it
curl -X POST "$API/api/tool" \
  -H "Content-Type: application/json" \
  -d @mytool.json
```

> The gateway maps `category_name` to the UUID automatically. If the category does not exist yet, create it first via `POST /api/category`.

### Option B — Python one-liner

```python
import requests, json
resp = requests.post(
    "http://localhost:8000/api/tool",
    json=json.load(open("mytool.json"))
)
print(resp.status_code, resp.json())
```

### Option C — Update an existing tool

```bash
# Get the tool_id first
curl "$API/api/tool?tool_name=mytool"

# Then PATCH
curl -X PATCH "$API/api/tool/<tool_id>" \
  -H "Content-Type: application/json" \
  -d @mytool.json
```

---

## Step 3 — Verify Registration <a name="step-3"></a>

```bash
# 1. List all tools — confirm your tool appears
curl "$API/api/tool" | python3 -m json.tool | grep tool_name

# 2. Get your tool specifically
curl "$API/api/tool?tool_name=mytool"

# 3. Pull the Docker image manually (optional, the server pulls on first run)
docker pull vendor/mytool:v1.0.0

# 4. Submit a test scan via the CLI or API and watch SSE output
./aof scan mytool -target example.com
```

---

## Complete JSON Reference <a name="reference"></a>

### Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `category_name` | string | ✅ | Must match an existing category (e.g. `"Reconnaissance"`, `"Vulnerability Scanning"`) |
| `tool_name` | string | ✅ | Unique. Used as the CLI subcommand name. Lowercase, no spaces. |
| `tool_description` | string | ✅ | Short one-liner for UI cards |
| `tool_long_description` | string | | Paragraph for tool detail / docs |
| `examples` | array | | Example input objects shown in the UI |
| `install_method` | string | ✅ | Always `"docker"` for registry images |
| `version` | string | ✅ | Semantic version (e.g. `"1.9.0"`) |
| `image_ref` | string | ✅ | Full Docker image reference (e.g. `"projectdiscovery/httpx:v1.9.0"`) |
| `image_source` | string | ✅ | `"dockerhub"` or `"custom"` (custom = locally built) |
| `is_active` | bool | ✅ | Set `true`. Use `SetToolActive` API to disable without deleting. |
| `denied_options` | array | ✅ | Flags users are **never** allowed to pass. Always deny output redirect flags. |

---

### `input_schema`

Controls how the tool receives its input — from user-submitted fields or from a previous step in the pipeline.

```json
"input_schema": {
  "type": "object",
  "pipeline_input": {
    "multi_mode": "list_file",   // OR "first" — see below
    "list_flag": "-list",         // the tool's flag for reading a file of targets
    "target_field": "target"      // which field in "fields" is the primary target
  },
  "fields": [
    {
      "key": "target",
      "type": "string",
      "required": true,
      "flag": "-u",               // CLI flag the tool uses for single-target input
      "description": "Target..."
    }
  ]
}
```

**`pipeline_input.multi_mode` values:**

| Value | When to use | Effect |
|---|---|---|
| `"list_file"` | Tool accepts a file of targets (`-list`, `-iL`) | Previous step's output is written to a temp file; `list_flag` points the tool at it |
| `"first"` | Tool only accepts a single target | First line of previous step's output is passed directly |

> **Rule:** If the tool has a `-list` / `-iL` / `-l` style flag → use `list_file`. Otherwise `first`.

---

### `output_schema`

Controls three things simultaneously: **SSE display**, **DB table columns**, and **pipeline chaining**.

```json
"output_schema": {
  "type": "array",
  "pipeline_output": {
    "mode": "jsonl",
    "extract_field": "url",   // field whose value is passed to the next tool
    "entity": "url",          // entity type label (url, host, vulnerability...)
    "dedupe": true            // deduplicate pipe lines?
  },
  "fields": [
    {
      "key": "url",
      "type": "string",
      "label": "URL",
      "description": "...",
      "finding_host": true,        // ← marks this as the primary display + finding host
      "pipeline_extract": true     // ← marks this as the value passed to next step
    },
    {
      "key": "status_code",
      "type": "integer",
      "label": "Status"
      // no special flags → shown in brackets [200] in SSE
    },
    {
      "key": "tech",
      "type": "array",
      "label": "Technologies"
      // arrays are comma-joined → [Bootstrap,jQuery]
    }
  ]
}
```

**Field flags that control SSE display:**

| Flag | Effect on SSE line |
|---|---|
| `"pipeline_extract": true` OR `"finding_host": true` | **Primary** — shown first, no brackets |
| `"finding_title": true` | Secondary — shown in `[brackets]` |
| Neither | Secondary — shown in `[brackets]` IF the value is present in JSON |
| `"key": "input"` | **Always skipped** in SSE display (it's the passthrough input) |

**The SSE line is built as:**
```
<primary>  [field2]  [field3]  [field4]
```
Only fields that actually have values in the JSON output are included. So if the user didn't enable `-title`, no title bracket appears — exactly like a real terminal.

---

### `shadow_output_config`

**This is the most critical section.** It controls whether the tool uses the streaming fan-out path or the shadow-file path.

#### Pattern A — JSONL on stdout (subfinder, httpx, nuclei, katana, naabu)

```json
"shadow_output_config": {
  "preferred_format": "jsonl",
  "formats": {
    "jsonl": {
      "transport": "stdout",          // ← triggers ClassStdoutJSONL fan-out
      "enable_flags": ["-silent", "-json"],  // flags injected automatically
      "parser": "jsonl",
      "path_mode": "streaming"
    }
  },
  "default_path": "/tmp/shadow/mytool",
  "filename_template": "{job_id}_{step_id}_{tool_name}_{timestamp}",
  "parse_timeout_seconds": 30,
  "fallback_to_stdout": true,
  "is_streaming": true
}
```

> **`transport: "stdout"`** → the Go backend fans each JSONL line to SSE + DB + pipe simultaneously in real time.  
> `enable_flags` are **added automatically** to every run — users never see them. They force structured output.

#### Pattern B — Structured file output (nmap, masscan)

```json
"shadow_output_config": {
  "preferred_format": "xml",
  "formats": {
    "xml": {
      "transport": "file",            // ← triggers ClassFileOnly path
      "path_flag": "-oX",             // flag the tool uses to set output file path
      "parser": "xml",
      "path_mode": "file",
      "file_extension": ".xml"
    }
  },
  "default_path": "/tmp/shadow/mytool",
  "filename_template": "{job_id}_{step_id}_{tool_name}_{timestamp}",
  "parse_timeout_seconds": 30,
  "fallback_to_stdout": false,
  "is_streaming": true
}
```

> **`transport: "file"`** → the backend bind-mounts a host directory into the container, injects `-oX /tmp/shadow/...` automatically, and reads the file after the container exits.  
> Stdout is streamed to SSE as raw human log lines (already readable).

---

### `parser_config`

Tells the findings parser which JSON/XML fields map to which finding columns.

```json
"parser_config": {
  "type": "jsonl",               // "jsonl" or "xml"
  "field_mappings": {
    "host":        ["url", "input"],           // tries "url" first, falls back to "input"
    "title":       ["title"],
    "severity":    "severity",                 // can be a string or array
    "description": ["description"],
    "metadata":    ["status_code", "tech", "content_type", "server"]
  },
  "default_severity": "SEVERITY_INFO",          // used when severity field is absent
  "fingerprint_fields": ["url"]                 // used for deduplication
}
```

**`field_mappings` keys:**

| Key | Maps to DB column | Notes |
|---|---|---|
| `host` | `findings.host` | Tried in order; first non-empty value wins |
| `title` | `findings.title` | |
| `severity` | `findings.severity` | Values: `critical`, `high`, `medium`, `low`, `info` |
| `description` | `findings.description` | |
| `metadata` | `findings.parsed_data` | All listed fields are collected into the metadata JSON |

**`fingerprint_fields`:** combined to create a unique hash for deduplication. Choose fields that make the finding unique (e.g. `["url"]` for httpx, `["template-id", "matched-at"]` for nuclei).

---

### `scan_config`

Exposes tool options to users. Three tiers:

```json
"scan_config": {
  "basic": {
    "presets": [
      {
        "name": "light",
        "description": "Quick scan",
        "flags": ["-fast"]          // flags injected when user picks this preset
      },
      {
        "name": "deep",
        "description": "Full scan",
        "flags": ["-all", "-comprehensive"]
      }
    ]
  },
  "medium": {
    "options": [
      {
        "flag": "-timeout",
        "key": "timeout",
        "type": "integer",
        "description": "Timeout in seconds",
        "required": false
      },
      {
        "flag": "-threads",
        "key": "threads",
        "type": "integer",
        "description": "Worker threads",
        "required": false
      }
    ]
  },
  "advanced": {
    "options": []               // leave empty — advanced scan reads from input_schema directly
  }
}
```

**Option types:**

| `type` | CLI rendering | Example |
|---|---|---|
| `"boolean"` | flag present or absent | `-sc` |
| `"integer"` | `flag value` | `-threads 10` |
| `"string"` | `flag value` | `-severity high,medium` |
| `"array"` | `flag value` (repeated or comma-joined) | `-header "X-Auth: xyz"` |

---

### `denied_options`

**Always include** flags that could:
- Write output to files (`-o`, `-oX`, `-oN`, `-oG`, `-csv`, etc.) — the backend controls output paths
- Read input from files that users could craft (`-l`, `-list`, `-iL`) — the backend controls input
- Enable dangerous behaviour (`--proxy`, `--interactsh-url`, etc.)

```json
"denied_options": ["-o", "-output", "-l", "-list", "-csv", "-json"]
```

> Note: `-json` is only denied if you don't want users forcing JSON mode manually. For tools where `enable_flags` already injects `-json`, adding it to `denied_options` prevents duplicate/conflicting flags.

---

## Output Class Decision Tree <a name="output-class"></a>

```
Does the tool write structured output to a file by default
(e.g. -oX, -oJ, --output)?
        │
       YES → ClassFileOnly
        │    shadow_output_config.formats.*.transport = "file"
        │    Stdout → SSE as raw text.
        │    File read after container exits → parseFindingsFromOutput
        │
        NO → Does the tool support -json / -jsonl flag on stdout?
              │
             YES → ClassStdoutJSONL
              │    shadow_output_config.formats.*.transport = "stdout"
              │    enable_flags: ["-silent", "-json"]
              │    Per-line fan-out: SSE + DB + pipe simultaneously.
              │
              NO → Still ClassFileOnly, but parser will use stdout text.
                   Set fallback_to_stdout: true in shadow_output_config.
```

---

## SSE Display Formatting <a name="sse-display"></a>

The SSE display is **fully automatic** — no code change required. It's driven entirely by `output_schema.fields`.

**How to control what appears in brackets:**

```json
// Only "url" is pipeline_extract → primary, no brackets.
// "status_code" appears as [200].
// "tech" appears as [Bootstrap,jQuery].
// "input" is always skipped.
// Fields with null/missing values are silently omitted.
```

**To hide a field from SSE display** while still storing it in the DB:  
→ Keep it in `parser_config.field_mappings.metadata` but remove it from `output_schema.fields`.

**The SSE format:**
```
<primary_field>  [secondary1]  [secondary2]  ...
```
Example outputs for common tools:
```
https://apply.cadt.edu.kh [200] [Bootstrap:5.0.2,jQuery:3.6.0]    ← httpx -sc -td
api.cadt.edu.kh [certspotter,bevigil]                               ← subfinder
192.168.1.1:80 [80]                                                 ← naabu
https://x.com [high] [cve-2021-1234] [SQL Injection]              ← nuclei
```

---

## Pipeline Chaining <a name="pipeline"></a>

Pipeline chaining is automatic when:
1. Tool A's `output_schema.pipeline_output.extract_field` names the field to extract
2. Tool B's `input_schema.pipeline_input.target_field` names the field it accepts

**Example:** subfinder → httpx

```
subfinder output_schema.pipeline_output.extract_field = "host"
   ↓ (each subdomain written to /tmp/pipe/<step>.txt)
httpx input_schema.pipeline_input.multi_mode = "list_file"
      input_schema.pipeline_input.list_flag = "-list"
   ↓ (httpx -list /tmp/pipe/subfinder.txt ...)
```

The backend handles the temp file creation and flag injection automatically.

**Deduplication** is controlled by `pipeline_output.dedupe: true`. Always set this to `true` for host/URL-type outputs.

---

## Common Mistakes Checklist <a name="checklist"></a>

Before submitting a new tool, verify:

- [ ] `tool_name` is **unique** and lowercase with no spaces
- [ ] `image_ref` is the full image path including tag (not `:latest` for production)
- [ ] `shadow_output_config.formats.*.transport` is correctly set to `"stdout"` or `"file"`
- [ ] `shadow_output_config.formats.*.enable_flags` includes ALL flags needed to force JSON/structured output
- [ ] Output flags (`-o`, `-oX`, `-csv`, etc.) are in `denied_options` to prevent users from overriding
- [ ] Input flags (`-list`, `-iL`, `-l`) are in `denied_options` to prevent path injection
- [ ] `output_schema.fields` has exactly **one** field with `"pipeline_extract": true` OR `"finding_host": true`
- [ ] `parser_config.fingerprint_fields` contains enough fields to uniquely identify a finding (prevents duplicate DB rows)
- [ ] `parser_config.field_mappings.host` is set (required for the finding to have a host value)
- [ ] `input_schema.pipeline_input.multi_mode` is correct (`list_file` if the tool has a list flag, `first` otherwise)
- [ ] Tested `docker run <image_ref> <command> -json` manually and confirmed JSON output format matches `output_schema.fields`

---

## Real Examples <a name="examples"></a>

### Adding `katana` (web crawler, JSONL stdout)

```json
{
  "category_name": "Reconnaissance",
  "tool_name": "katana",
  "tool_description": "Fast web crawler and spider",
  "tool_long_description": "Katana is a next-generation web crawling framework from ProjectDiscovery. It crawls and extracts URLs, endpoints, and JavaScript files from web applications.",
  "examples": [{ "url": "https://example.com" }],
  "input_schema": {
    "type": "object",
    "pipeline_input": {
      "multi_mode": "list_file",
      "list_flag": "-list",
      "target_field": "url"
    },
    "fields": [
      {
        "key": "url",
        "type": "string",
        "required": true,
        "flag": "-u",
        "description": "Target URL to crawl"
      }
    ]
  },
  "output_schema": {
    "type": "array",
    "pipeline_output": {
      "mode": "jsonl",
      "extract_field": "endpoint",
      "entity": "url",
      "dedupe": true
    },
    "fields": [
      {
        "key": "endpoint",
        "type": "string",
        "label": "Endpoint",
        "finding_host": true,
        "pipeline_extract": true
      },
      {
        "key": "source",
        "type": "string",
        "label": "Source"
      },
      {
        "key": "tag",
        "type": "string",
        "label": "Tag"
      }
    ]
  },
  "scan_config": {
    "basic": {
      "presets": [
        { "name": "light", "description": "Crawl depth 1", "flags": ["-depth", "1"] },
        { "name": "deep",  "description": "Crawl depth 3", "flags": ["-depth", "3"] }
      ]
    },
    "medium": {
      "options": [
        { "flag": "-depth",   "key": "depth",       "type": "integer", "description": "Crawl depth",              "required": false },
        { "flag": "-timeout", "key": "timeout",      "type": "integer", "description": "Timeout per request (s)", "required": false },
        { "flag": "-c",       "key": "concurrency",  "type": "integer", "description": "Concurrent crawlers",     "required": false }
      ]
    },
    "advanced": { "options": [] }
  },
  "install_method": "docker",
  "version": "1.1.0",
  "image_ref": "projectdiscovery/katana:v1.1.0",
  "image_source": "dockerhub",
  "is_active": true,
  "denied_options": ["-list", "-o", "-output", "-csv"],
  "shadow_output_config": {
    "preferred_format": "jsonl",
    "formats": {
      "jsonl": {
        "transport": "stdout",
        "enable_flags": ["-silent", "-json"],
        "parser": "jsonl",
        "path_mode": "streaming"
      }
    },
    "default_path": "/tmp/shadow/katana",
    "filename_template": "{job_id}_{step_id}_{tool_name}_{timestamp}",
    "parse_timeout_seconds": 60,
    "fallback_to_stdout": true,
    "is_streaming": true
  },
  "parser_config": {
    "type": "jsonl",
    "field_mappings": {
      "host": ["endpoint"],
      "title": ["tag", "source"],
      "metadata": ["source", "tag"]
    },
    "default_severity": "SEVERITY_INFO",
    "fingerprint_fields": ["endpoint"]
  }
}
```

**SSE output:**
```
https://example.com/login [form] [a]
https://example.com/api/v1/users [script] [script]
```

---

### Adding `gobuster` in DNS mode (text stdout, no JSON)

```json
{
  "category_name": "Reconnaissance",
  "tool_name": "gobuster-dns",
  "tool_description": "DNS subdomain brute-forcer",
  "input_schema": {
    "type": "object",
    "pipeline_input": { "multi_mode": "first", "target_field": "domain" },
    "fields": [
      { "key": "domain", "type": "string", "required": true, "flag": "-d", "description": "Target domain" },
      { "key": "wordlist", "type": "string", "required": true, "flag": "-w", "description": "Wordlist path inside container" }
    ]
  },
  "output_schema": {
    "type": "array",
    "fields": [{ "key": "host", "type": "string", "label": "Subdomain", "finding_host": true }]
  },
  "scan_config": { "basic": { "presets": [] }, "medium": { "options": [] }, "advanced": { "options": [] } },
  "install_method": "docker",
  "version": "2.0.1",
  "image_ref": "ghcr.io/oj/gobuster:v2.0.1",
  "image_source": "custom",
  "is_active": true,
  "denied_options": ["-o", "--output"],
  "shadow_output_config": {
    "preferred_format": "text",
    "formats": {
      "text": {
        "transport": "stdout",
        "enable_flags": [],
        "parser": "lines",
        "path_mode": "streaming"
      }
    },
    "default_path": "/tmp/shadow/gobuster-dns",
    "filename_template": "{job_id}_{step_id}_{tool_name}_{timestamp}",
    "parse_timeout_seconds": 120,
    "fallback_to_stdout": true,
    "is_streaming": true
  },
  "parser_config": {
    "type": "lines",
    "field_mappings": { "host": ["host"] },
    "default_severity": "SEVERITY_INFO",
    "fingerprint_fields": ["host"]
  }
}
```

---

*Document maintained by: Auto-Offensive Admin*  
*Last updated: see git log*
