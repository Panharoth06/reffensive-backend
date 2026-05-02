# Advanced Scan Flow — Architecture & Execution Guide

## Table of Contents

1. [Overview](#overview)
2. [Key Components](#key-components)
3. [Data Model](#data-model)
4. [Request Submission Flow](#request-submission-flow)
5. [Queue-Based Execution](#queue-based-execution)
6. [Command Parsing Flow](#command-parsing-flow)
7. [Step Execution Flow](#step-execution-flow)
8. [Output Classes: JSONL Streaming vs File-Based](#output-classes-jsonl-streaming-vs-file-based)
9. [Real-Time Log Streaming (Fan-Out)](#real-time-log-streaming-fan-out)
10. [Pipeline Transport (Inter-Step Piping)](#pipeline-transport-inter-step-piping)
11. [Shadow Output Capture](#shadow-output-capture)
12. [Result Persistence & Finding Extraction](#result-persistence--finding-extraction)
13. [Idempotency Mechanism](#idempotency-mechanism)
14. [Policy & Security Deny List](#policy--security-deny-list)
15. [Runtime Configuration (gVisor / Network / Capabilities)](#runtime-configuration-gvisor--network--capabilities)
16. [Status Tracking & Job Lifecycle](#status-tracking--job-lifecycle)
17. [Background Cleanup](#background-cleanup)

---

## Overview

The `advanced_scan` module implements a **multi-step, pipelined, Docker-based security scanning system**. Users submit Unix-style pipeline commands (e.g. `subfinder -d example.com | httpx -silent`) that are parsed into sequential steps. Each step runs in an isolated Docker container, with output from one step piped as input to the next.

### Architecture Highlights

- **Queue-Based Execution**: Jobs are enqueued via Redis and processed by a shared queue manager with capacity limits
- **Dual Output Classes**: Tools are classified as `ClassStdoutJSONL` (real-time streaming) or `ClassFileOnly` (post-run file capture)
- **Real-Time Fan-Out**: JSONL tools stream output to SSE, shadow buffers, and pipeline inputs simultaneously
- **Policy Enforcement**: Global and per-tool deny lists block dangerous flags
- **Isolation**: gVisor runtime, network mode restrictions, and no privileged execution

```mermaid
flowchart TD
    classDef client fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#000
    classDef server fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#000
    classDef queue fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef worker fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#000
    classDef database fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#000
    classDef redis fill:#fff8e1,stroke:#ffa000,stroke-width:2px,color:#000

    Client["Client (gRPC)"]:::client --> SubmitScan["SubmitScan RPC<br/>submit.go"]:::server
    SubmitScan -->|"1. Parse command<br/>2. Validate auth/project<br/>3. Create DB records<br/>4. Enqueue to Redis"| Queue[("Redis Queue<br/>shared queue manager")]:::queue

    Queue -->|"Dequeue job"| Worker["ProcessJob<br/>queue_worker.go"]:::worker
    Worker -->|"Reconstruct chain spec"| Chain["executeStepChain<br/>execute.go"]:::worker

    Chain -->|"For each step:<br/>• Resolve output class<br/>• Build invocation plan<br/>• Prepare pipeline input<br/>• Run Docker container<br/>• Capture output<br/>• Persist findings<br/>• Publish logs via Redis<br/>• Pipe output to next step"| PG[("PostgreSQL<br/>Jobs, Steps, Findings, Results")]:::database

    Chain -->|"Pub/Sub real-time<br/>log streaming"| Redis[("Redis Pub/Sub<br/>scan:logs:stepID")]:::redis
```

---

## Key Components

| File                    | Responsibility                                                                                |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `advanced_scan.go`      | Server struct, constructor, in-memory state, background cleanup                               |
| `submit.go`             | `SubmitScan` RPC, idempotency, target resolution, DB creation, queue enqueue                  |
| `queue_worker.go`       | `ProcessJob` — dequeues jobs from Redis, reconstructs chain specs, executes step chain        |
| `execute.go`            | `executeStepChain` — sequential Docker execution, output class dispatch, failure handling     |
| `stream_fanout.go`      | `runStdoutJSONLStep` / `runFileOnlyStep` — output class execution paths                       |
| `command_parser.go`     | Unix pipeline parsing (pipe splitting), quote-aware tokenization, step token parsing          |
| `policy.go`             | `BuildAdvancedInvocation` — flag validation, denied flags, input injection, argv construction |
| `pipeline_transport.go` | Inter-step data piping — list file transport, line extraction, deduplication                  |
| `shadow_transport.go`   | Shadow output preparation/capture — file mount, format selection, stdout fallback             |
| `runtime_config.go`     | Docker runtime resolution — gVisor, network mode, capabilities                                |
| `image_policy.go`       | Image pull policy based on tool source (dockerhub vs custom/local)                            |
| `logging.go`            | `publishLog` — Redis Pub/Sub log streaming to clients                                         |
| `results.go`            | `GetResults` RPC, findings pagination/filtering, raw output/parse metadata lookup             |
| `persistence.go`        | Artifact writing, finding parsing (XML/JSON/line), DB writes, severity normalization          |
| `helpers.go`            | Utilities — idempotency hash, job status derivation, status sync                              |
| `status.go`             | Protobuf ↔ DB status mapping, runtime snapshots                                               |

---

## Data Model

### In-Memory State (per server instance)

```mermaid
classDiagram
    class advancedScanServer {
        +jobs map[string]*jobRuntime
        +steps map[string]*stepRuntime
        +idempotent map[string]*idempotencyEntry
        +redisClient *redis.Client
        +redisChannelPrefix string
        +artifactRoot string
    }

    class jobRuntime {
        +string JobID
        +string ProjectID
        +JobStatus Status
        +time CreatedAt
        +time StartedAt
        +time FinishedAt
        +string[] StepIDs
    }

    class stepRuntime {
        +string StepID
        +string JobID
        +string ToolName
        +StepStatus Status
        +time QueuedAt
        +time StartedAt
        +time FinishedAt
        +int64 ExitCode
        +int32 Findings
        +bool HasParsedData
        +string Error
        +string ArtifactPath
        +InvocationPlan CommandPlan
        +int64 SequenceNum
        +LogChunk[] Logs (capped 2000)
    }

    class idempotencyEntry {
        +string RequestHash
        +SubmitScanResponse Response
        +time CreatedAt
    }

    advancedScanServer "1" --> "*" jobRuntime : jobs
    advancedScanServer "1" --> "*" stepRuntime : steps
    advancedScanServer "1" --> "*" idempotencyEntry : idempotent
    jobRuntime "1" --> "*" stepRuntime : references
```

### Database Tables (PostgreSQL via sqlc)

```mermaid
erDiagram
    scan_jobs ||--o{ scan_steps : "contains"
    scan_steps ||--o{ scan_results : "produces"
    scan_steps ||--o{ findings : "discovers"
    scan_results ||--o{ findings : "source"
    projects ||--o{ scan_jobs : "owns"
    projects ||--o{ targets : "contains"
    projects ||--o{ findings : "belongs to"
    targets ||--o{ scan_jobs : "scanned by"
    tools ||--o{ scan_steps : "executed as"
    tools ||--o{ scan_results : "output from"

    scan_jobs {
        uuid job_id PK
        uuid project_id FK
        uuid target_id FK
        uuid triggered_by
        execution_mode execution_mode
        scan_job_status status
        timestamptz created_at
        timestamptz finished_at
        interval scan_duration
    }

    scan_steps {
        uuid step_id PK
        uuid job_id FK
        uuid tool_id FK
        text tool_version
        input_source_type input_source
        uuid input_step_id FK
        string step_key
        int step_order
        scan_step_status status
        timestamptz started_at
        timestamptz finished_at
    }

    scan_results {
        uuid result_id PK
        uuid step_id FK
        uuid job_id FK
        uuid project_id FK
        uuid target_id FK
        uuid tool_id FK
        jsonb raw_data
        jsonb parsed_data
        severity_level severity
        scan_step_status status
        timestamptz started_at
        timestamptz finished_at
    }

    findings {
        uuid finding_id PK
        uuid project_id FK
        uuid job_id FK
        uuid step_id FK
        uuid tool_id FK
        severity_level severity
        text title
        text host
        int port
        text fingerprint "SHA-256 dedup key"
        uuid raw_result_id FK
        timestamptz created_at
    }

    targets {
        uuid target_id PK
        uuid project_id FK
        string name
        string type "domain/ip/url/cidr"
        text description
    }

    projects {
        uuid project_id PK
        uuid user_id FK
        string project_name
    }

    tools {
        uuid tool_id PK
        string tool_name
        string image_ref
        string image_source
        jsonb input_schema
        jsonb output_schema
        jsonb scan_config
        text[] denied_options
        jsonb shadow_output_config
    }
```

---

## Request Submission Flow

### Entry Point: `SubmitScan` RPC (`submit.go`)

```mermaid
flowchart TD
    classDef start fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef subgraph_style fill:#f5f5f5,stroke:#9e9e9e,stroke-width:2px,color:#000
    classDef endnode fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef success fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef error fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000

    Start([Client SubmitScan Request]):::start --> ValidateProject["Validate project_id is valid UUID"]:::process
    ValidateProject --> GenIdem["Generate idempotency_key if missing"]:::process
    GenIdem --> Normalize["normalizeSubmittedStepsForRequest<br/>parse command string → submittedStepInput[]"]:::process

    subgraph Parse ["Command Parsing"]
        Normalize --> Split["splitUnixCommandPipeline<br/>splits on | preserving quotes"]:::process
        Split --> Tokens["parseCommandStepTokens<br/>maps flags → tool_args, raw custom flags"]:::process
        Tokens --> DeriveTarget["deriveTargetValueFromStep<br/>extracts target from first step"]:::process
    end

    DeriveTarget --> ValidateTool["Validate at least one tool"]:::process
    ValidateTool --> FillTarget["If target_id and target_value are both empty:<br/>use derived target from first step"]:::process
    FillTarget --> HashReq:::process

    subgraph Idempotency ["Idempotency Check"]
        HashReq["idempotencyHashForRequest<br/>SHA-256 hash (excludes retry fields)"]:::process --> CheckCache{"In idempotent cache?"}:::decision
        CheckCache -->|"Found + same hash"| Replay["Replay cached response<br/>IsIdempotentReplay = true<br/>OriginalRequestId = original first step_id"]:::success
        CheckCache -->|"Found + different hash"| AlreadyExists["AlreadyExists error"]:::error
        CheckCache -->|"Found + no response"| Aborted["Aborted — retry shortly"]:::error
        CheckCache -->|"Not found"| Register["Register entry, continue"]:::process
    end

    Replay --> End([Return Response]):::endnode
    AlreadyExists --> EndFail1([Error]):::error
    Aborted --> EndFail2([Error]):::error

    Register --> BuildChain["For each step:<br/>• Resolve tool from DB<br/>• Validate custom flags syntax<br/>• Build chainStepSpec list"]:::process
    BuildChain --> ValidateIDs["Validate optional job_id / step_id UUIDs"]:::process
    ValidateIDs --> AuthCheck["Auth: RequireUserID from interceptor"]:::process
    AuthCheck --> VerifyProject["Verify project belongs to user"]:::process
    VerifyProject --> ResolveTarget{"Resolve or create target?"}:::decision

    ResolveTarget -->|"target_id is UUID"| LookupTarget["Lookup existing target by UUID"]:::process
    ResolveTarget -->|"target_id is non-UUID"| FallbackTarget["Treat target_id as target_value<br/>(backward-compatible fallback)"]:::process
    ResolveTarget -->|"target_value provided"| CheckExisting["Check existing by name<br/>(case-insensitive, trimmed)"]:::process
    FallbackTarget --> CheckExisting
    CheckExisting -->|"found"| UseExisting["Use existing target"]:::process
    CheckExisting -->|"not found"| CreateTarget["CREATE target<br/>with inferred type<br/>(domain/ip/url/cidr)"]:::process

    LookupTarget --> CreateJob["CreateScanJob in DB"]:::process
    UseExisting --> CreateJob
    CreateTarget --> CreateJob
    CreateJob --> CreateSteps["For each step:<br/>CreateScanStep, set PENDING<br/>Fill UUIDs into chain spec"]:::process
    CreateSteps --> BuildResp["Build SubmitScanResponse<br/>job_id, first step_id, status=QUEUED"]:::process
    BuildResp --> RegisterMemory["Register job + steps in-memory<br/>Update idempotency entry"]:::process
    RegisterMemory --> PublishQueued["Publish 'step queued' logs via Redis"]:::process
    PublishQueued --> BuildPayload["Build queuePayload<br/>with steps, execution_config, shadow_config"]:::process
    BuildPayload --> Enqueue["qm.EnqueueWithCapacityCheck<br/>enqueue to Redis queue"]:::process

    Enqueue --> QueueFull{"Queue full?"}:::decision
    QueueFull -->|"Yes"| QueueFullResp["Return QUEUED response<br/>status=QUEUE_FULL, retry_after=60s"]:::process
    QueueFull -->|"No"| LaunchWorker["Worker dequeues → ProcessJob<br/>→ executeStepChain in background"]:::process

    QueueFullResp --> ReturnResp["Return response immediately"]:::process
    LaunchWorker --> ReturnResp
    ReturnResp --> End([Response to Client]):::endnode
```

---

## Queue-Based Execution

### How Jobs Flow Through the System

Unlike traditional direct execution, advanced scan jobs flow through a **Redis-backed queue** with a shared worker pool:

```mermaid
flowchart LR
    classDef submit fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef worker fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef execute fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef complete fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef queue fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#000

    subgraph Submit ["Submit Phase"]
        S1[Client]:::submit -->|"SubmitScan"| S2[Server]:::submit
        S2 -->|"EnqueueWithCapacityCheck"| S3[("Redis Queue<br/>FIFO, capacity-limited")]:::queue
    end

    subgraph Worker ["Worker Pool (started by queue.InitManager)"]
        W1[Worker 1]:::worker & W2[Worker 2]:::worker & W3[Worker N]:::worker -->|"Dequeue"| S3
    end

    subgraph Execute ["Execution Phase"]
        W1 -->|"ProcessJob"| E1[Reconstruct chain spec]:::execute
        E1 --> E2[Re-resolve tools from DB]:::execute
        E2 --> E3[Build SubmitScanRequest from payload]:::execute
        E3 --> E4[executeStepChain]:::execute
    end

    subgraph Complete ["Completion"]
        E4 --> C1["Manager.Complete(receipt)"]:::complete
        C1 --> S3
    end
```

### `ProcessJob` Flow (`queue_worker.go`)

1. **Dequeue**: Worker receives job payload from Redis queue
2. **Reconstruct**: Rebuild `chainStepSpec[]` from payload steps
3. **Re-resolve**: Look up each tool from DB (ensures fresh config)
4. **Build Request**: Reconstruct `SubmitScanRequest` from execution_config and shadow_config JSON
5. **Execute**: Call `executeStepChain(request, chain)`
6. **Complete**: Mark job as complete in queue manager

---

## Command Parsing Flow

The advanced scan accepts a **Unix-style pipeline command** instead of structured tool args. Example:

```
subfinder -d example.com -silent | httpx -path /login -silent | naabu -top-ports 1000
```

### Step 1: `splitUnixCommandPipeline`

A custom tokenizer that:

- Splits on `|` (pipe character)
- **Preserves quoted strings** (single and double quotes)
- Handles escape sequences (`\`)
- Rejects unterminated quotes or escapes

```
Input:  subfinder -d "example.com" | httpx -path '/admin area' -silent

Output: [["subfinder", "-d", "example.com"], ["httpx", "-path", "/admin area", "-silent"]]
```

### Step 2: `parseCommandStepTokens` (per segment)

For each tokenized segment:

1. Resolve tool by first token (tool name)
2. Parse input_schema and scan_config JSON
3. Build input flag index (normalized flag → field spec)
4. Build option index (scan_config options)
5. Iterate remaining tokens:
   - **Input flags** (from input_schema) → map to `ToolArgs[key]`
   - **Option flags** (from scan_config) → map to `ToolArgs[key]` as strings
   - **Unknown flags** → append to `RawCustomFlags`
   - **Positional args** → map to positional input fields (fields without a flag)

Type coercion for declared option values happens later in `buildAdvancedInvocation`, not during command parsing.

### Step 3: Target Derivation

From the first step, extract the target value by checking:

1. Preferred keys: `target`, `host`, `hostname`, `domain`, `url`, `ip`, `cidr`
2. First non-empty input field as fallback

---

## Step Execution Flow

### `executeStepChain` — The Core Loop (`execute.go`)

```mermaid
flowchart TD
    classDef loop fill:#f5f5f5,stroke:#616161,stroke-width:2px,color:#000
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef fail fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef success fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef endnode fill:#e0e0e0,stroke:#424242,stroke-width:2px,color:#000

    LoopStart["for idx, spec := range chain"]:::loop --> MarkRunning["markStepRunning<br/>DB + in-memory → RUNNING"]:::process
    MarkRunning --> ParseScanCfg["parseScanConfig for runtime"]:::process
    ParseScanCfg --> ResolveRuntime["resolveToolRuntime<br/>(gVisor, network, capabilities)"]:::process
    ResolveRuntime --> LogStart["Publish 'starting docker container'"]:::process

    LogStart --> IsFirstStep{"idx > 0?"}:::decision
    IsFirstStep -->|"Yes"| PreparePipe["preparePipelineInput<br/>pipe previous step output"]:::process
    IsFirstStep -->|"No"| ParseFlags:::process

    PreparePipe --> PipeMode{"multi_mode?"}:::decision
    PipeMode -->|"list_file"| ListFile["Create ContainerFile<br/>Inject -list flag<br/>Mount as container file"]:::process
    PipeMode -->|"default"| ApplyPipe["ApplyPipeInputs<br/>fill first missing required"]:::process

    ListFile --> ParseFlags["Parse custom flags from raw"]:::process
    ApplyPipe --> ParseFlags

    ParseFlags --> SetTarget["Set target value<br/>(only for first step)"]:::process
    SetTarget --> BuildInvocation["buildAdvancedInvocation<br/>policy validation"]:::process

    BuildInvocation --> ValidateInputs{"Required inputs<br/>present?"}:::decision
    ValidateInputs -->|"No"| FailPolicy["FAILED: missing inputs"]:::fail
    ValidateInputs -->|"Yes"| CheckDenied{"Any denied flags?"}:::decision
    CheckDenied -->|"Yes"| FailDenied["FAILED: globally/per-tool denied"]:::fail
    CheckDenied -->|"No"| BuildArgv["Build argv:<br/>flagged inputs → positional<br/>→ options → custom flags"]:::process

    BuildArgv --> PrepareShadow["prepareShadowOutput<br/>prepare file mount"]:::process
    PrepareShadow --> AddShadowArgs["If enabled: add -oX/-oJ<br/>+ volume mount"]:::process

    AddShadowArgs --> ResolveClass["resolveOutputClass<br/>(JSONL vs FileOnly)"]:::process

    ResolveClass --> ClassCheck{"Output class?"}:::decision
    ClassCheck -->|"ClassStdoutJSONL"| RunJSONL["runStdoutJSONLStep<br/>real-time fan-out streaming"]:::process
    ClassCheck -->|"ClassFileOnly"| RunFile["runFileOnlyStep<br/>post-run shadow capture"]:::process

    RunJSONL --> HandleJSONL["Handle JSONL result:<br/>• Set status<br/>• persistJSONLShadow<br/>• Extract pipe lines"]:::process
    RunFile --> HandleFile["Handle File result:<br/>• captureShadowOutput<br/>• writeShadowArtifact<br/>• persistStepResult<br/>• Extract pipe lines"]:::process

    HandleJSONL --> DetermineStatus{"Status COMPLETED?"}:::decision
    HandleFile --> DetermineStatus

    DetermineStatus -->|"Yes"| UpdateMem["Update in-memory step<br/>recompute job status"]:::success
    DetermineStatus -->|"No"| UpdateMem

    UpdateMem --> SyncDB["Sync step + job status to DB"]:::process

    SyncDB --> SuccessCheck{"Step COMPLETED?"}:::decision
    SuccessCheck -->|"Yes"| ExtractPipe["extractPipelineOutputs<br/>→ pipedLines for next step"]:::process
    SuccessCheck -->|"No"| SkipRest["markRemainingSkipped<br/>mark rest as SKIPPED → return"]:::fail

    ExtractPipe --> LoopEnd{"More steps in chain?"}:::decision
    LoopEnd -->|"Yes"| LoopStart
    LoopEnd -->|"No"| ChainDone([Chain Complete]):::endnode
    SkipRest --> ChainDone
    FailPolicy --> SkipRest
    FailDenied --> SkipRest
```

### Failure Handling

| Scenario             | Behavior                                                                                               |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| Panic in goroutine   | Recover → publish panic log → finalize first step → skip rest                                          |
| Tool exits non-zero  | Status=FAILED → publish failure log → skip remaining steps                                             |
| Policy rejection     | Status=FAILED → error message includes rejection reason                                                |
| Pipeline input error | Status=FAILED → skip remaining steps                                                                   |
| Shadow output error  | `prepareShadowOutput` failure aborts the step; capture/write errors are logged and execution continues |
| Persistence error    | Logged as warning, findings count stays 0                                                              |

---

## Output Classes: JSONL Streaming vs File-Based

Tools are classified into two output classes based on their `shadow_output_config`:

### `ClassStdoutJSONL` — Real-Time Streaming

**Tools**: subfinder, httpx, nuclei, katana, etc.

**Configuration**: `shadow_output_config.formats[preferred].transport == "stdout"`

**Behavior**:

- Tool writes JSONL (one JSON object per line) to stdout
- Go reads stdout line-by-line and fans out to three targets simultaneously
- No shadow file on disk; no post-run buffering

```mermaid
flowchart LR
    classDef tool fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#000
    classDef runtime fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef output fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000

    subgraph Tool ["Tool Container"]
        T1["subfinder/httpx/nuclei"]:::tool -->|"JSONL stdout"| T2["api.example.com\nhttps://example.com [200]"]:::tool
    end

    subgraph Go ["Go Runtime (stream_fanout.go)"]
        T2 -->|"line-by-line"| FanOut["OnStdoutLine callback"]:::runtime
        FanOut --> SSE["1. SSE/Redis Pub/Sub<br/>Terminal-formatted line<br/>e.g. 'api.example.com [certspotter]'"]:::output
        FanOut --> Shadow["2. Shadow Buffer<br/>Raw JSONL line<br/>accumulated for DB"]:::output
        FanOut --> Pipe["3. Pipeline Output<br/>Extracted field (e.g. 'host')<br/>deduplicated for next step"]:::output
    end
```

### `ClassFileOnly` — Post-Run File Capture

**Tools**: nmap, masscan, gobuster (with -oX), etc.

**Configuration**: `shadow_output_config.formats[preferred].transport == "file"`

**Behavior**:

- Tool writes structured output to a file (e.g. `-oX report.xml`)
- Stdout emits human-readable log lines
- After container exits, Go reads the shadow file from the bind-mounted host path

```mermaid
flowchart LR
    classDef tool fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#000
    classDef docker fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef runtime fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    subgraph Tool ["Tool Container"]
        T1["nmap/masscan"]:::tool -->|"-oX /tmp/shadow/file.xml"| T2["XML/JSON file"]:::tool
        T1 -->|"log lines"| T3["stdout"]:::tool
    end

    subgraph Docker ["Docker Bind Mount"]
        T2 -->|"/tmp/shadow:/tmp/shadow"| HostPath["Host: /tmp/shadow/file.xml"]:::docker
    end

    subgraph Go ["Go Runtime (stream_fanout.go)"]
        T3 -->|"OnLog callback"| SSE["Redis Pub/Sub<br/>stdout lines"]:::runtime
        HostPath -->|"After exit"| ReadFile["captureShadowOutput<br/>poll file with timeout"]:::runtime
        ReadFile --> Parse["parseFindingsFromOutput<br/>XML/JSON/line parsers"]:::runtime
    end
```

---

## Real-Time Log Streaming (Fan-Out)

### `publishLog` (`logging.go`)

Every significant event during scan execution publishes a log chunk to Redis Pub/Sub:

```mermaid
flowchart TD
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef redis fill:#fff8e1,stroke:#ffa000,stroke-width:2px,color:#000
    classDef endnode fill:#e0e0e0,stroke:#424242,stroke-width:2px,color:#000

    Call["publishLog(stepID, toolName, source, line)"]:::process --> Trim["Trim trailing \\r, skip empty"]:::process
    Trim --> Lock["Acquire mutex lock"]:::process
    Lock --> Lookup{"Step in memory?"}:::decision
    Lookup -->|"No"| Unlock1["Release lock, return"]:::endnode
    Lookup -->|"Yes"| Increment["Increment SequenceNum"]:::process
    Increment --> BuildChunk["Build LogChunk protobuf"]:::process
    BuildChunk --> AppendLogs["Append to step.Logs<br/>(capped at 2000 — LRU trim)"]:::process
    AppendLogs --> Record["Record completion status<br/>+ is_final_chunk"]:::process
    Record --> Unlock2["Release lock"]:::process

    Unlock2 --> BuildPayload["Build JSON payload:<br/>step_id, job_id, tool_name,<br/>source, line, timestamp, sequence_num"]:::process
    BuildPayload --> Marshal["json.Marshal(payload)"]:::process
    Marshal --> Channel["Channel: scan:logs:stepID<br/>(configurable via REDIS_SCAN_LOG_PREFIX)"]:::redis
    Channel --> RedisPublish["Redis PUBLISH<br/>Timeout: 2s, fire-and-forget<br/>Errors silently ignored"]:::redis
    RedisPublish --> Done([Done]):::endnode
    Unlock1 --> Done
```

### Log Sources

| Source              | When Published                                                                      |
| ------------------- | ----------------------------------------------------------------------------------- |
| `LOG_SOURCE_SYSTEM` | Step queued, starting, container launch, shadow capture, completion, errors, panics |
| `LOG_SOURCE_STDOUT` | Each line from Docker container stdout                                              |
| `LOG_SOURCE_STDERR` | Each line from Docker container stderr                                              |

### Fan-Out for JSONL Tools (`stream_fanout.go`)

When a tool is `ClassStdoutJSONL`, each stdout line is fanned out to three targets:

1. **SSE/Redis Pub/Sub**: Terminal-formatted line for human viewing
   - Primary value (e.g. `api.example.com`) followed by bracket annotations
   - Example: `https://apply.cadt.edu.kh [200] [Bootstrap:5,jQuery:3.6]`
2. **Shadow Buffer**: Raw JSONL line accumulated for DB persistence
3. **Pipeline Output**: Extracted field value (e.g. `host`) deduplicated for next step

### Client Consumption

External systems (e.g. a WebSocket gateway) subscribe to `scan:logs:*` channels and forward messages to connected clients in real time:

```mermaid
flowchart LR
    classDef redis fill:#fff8e1,stroke:#ffa000,stroke-width:2px,color:#000
    classDef gateway fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef client fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#000

    Redis[("Redis Pub/Sub")]:::redis -->|"scan:logs:step-uuid-1"| WS["WebSocket<br/>Gateway"]:::gateway
    Redis -->|"scan:logs:step-uuid-2"| WS
    Redis -->|"scan:logs:step-uuid-3"| WS2["WebSocket<br/>Gateway 2"]:::gateway
    WS -->|"forward"| Browser["Browser Client"]:::client
    WS -->|"forward"| CLI["CLI Client"]:::client
    WS2 -->|"forward"| Dashboard["Dashboard Client"]:::client
```

---

## Pipeline Transport (Inter-Step Piping)

### How Output Flows Between Steps

```mermaid
flowchart LR
    classDef stdout fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#000
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef mode fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000

    subgraph Step1 ["Step 1 (subfinder) stdout"]
        Raw["a.example.com\nb.example.com\na.example.com"]:::stdout
    end

    Raw --> Extract["extractPipelineOutputs<br/>• Split by newline, trim<br/>• Remove empty lines<br/>• Deduplicate"]:::process
    Extract --> Clean["Deduplicated list<br/>a.example.com, b.example.com"]:::process

    Clean --> CheckMode{"Step 2<br/>multi_mode?"}:::decision

    CheckMode -->|"list_file"| ListFileMode["Create ContainerFile<br/>/tmp/advanced-scan-inputs/{job}_{step}.txt<br/>Content: deduped lines<br/>Inject: -list /tmp/.../{job}_{step}.txt"]:::mode
    CheckMode -->|"default"| ApplyPipeMode["ApplyPipeInputs<br/>Set first non-empty line<br/>to first missing<br/>required input field"]:::mode

    ListFileMode --> Step2["Step 2 receives<br/>piped input via file"]:::stdout
    ApplyPipeMode --> Step2Alt["Step 2 receives<br/>piped input via arg"]:::stdout
```

### Pipeline Modes

| Mode        | When to Use                            | Behavior                                                             |
| ----------- | -------------------------------------- | -------------------------------------------------------------------- |
| `list_file` | Tool accepts a file of targets         | Writes all piped lines to a container file, injects via `-list` flag |
| `default`   | Tool accepts a single target at a time | Takes first non-empty line, fills first missing required input field |

### Key Design Decisions

- **list_file mode**: Writes all piped lines to a file injected directly into the container (no host-side I/O).
- **Deduplication**: Happens both on extraction (output) and normalization (input).
- **Empty handling**: Blank lines and whitespace-only lines are silently dropped.

### JSONL Pipeline Extraction

For `ClassStdoutJSONL` tools, the pipeline output is extracted from JSON stdout:

1. Read `output_schema.pipeline_output.extract_field` (e.g. `"host"`)
2. For each JSON line, extract the field value
3. Fallback to common aliases: `host`, `url`, `input`, `ip`, `domain`
4. Deduplicate extracted values
5. Pass to next step

---

## Shadow Output Capture

Shadow output allows capturing **structured tool output** (e.g. nmap XML, JSON) alongside raw stdout.

### Configuration (tool's `shadow_output_config` JSON)

```json
{
  "preferred_format": "xml",
  "formats": {
    "xml": {
      "transport": "file",
      "path_flag": "-oX",
      "parser": "xml",
      "path_mode": "file",
      "file_extension": ".xml"
    }
  },
  "default_path": "/tmp/shadow",
  "fallback_to_stdout": true
}
```

### Flow

```mermaid
flowchart TD
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef prepare fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef capture fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef output fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#000

    subgraph Prepare ["prepareShadowOutput()"]
        P1["Parse config, validate<br/>preferred format exists"]:::prepare --> P2{"transport = file?"}:::decision
        P2 -->|"Yes"| P3["Create directory on host<br/>(default_path, mode 0o777)"]:::prepare
        P3 --> P4["Generate filename:<br/>{job_id}_{step_id}_{tool_name}_{timestamp}.xml"]:::prepare
        P4 --> P5["Add args: -oX /tmp/shadow/file.xml"]:::prepare
        P5 --> P6["Bind-mount host dir into container:<br/>/tmp/shadow:/tmp/shadow"]:::prepare
        P6 --> P7["Return preparedShadowOutput"]:::prepare
        P2 -->|"No (stdout)"| P7
    end

    P7 --> ContainerRuns["Container executes tool"]:::process

    subgraph Capture ["captureShadowOutput()"]
        ContainerRuns --> C1{"transport = file?"}:::decision
        C1 -->|"Yes"| C2["Poll HostPath with timeout<br/>(default 30s, 100ms interval)"]:::capture
        C2 --> C3{"File exists?"}:::decision
        C3 -->|"Yes"| C4["Read file content"]:::capture
        C3 -->|"No"| C4b["fallback_to_stdout?"]:::decision
        C4b -->|"Yes"| C5["Use captured stdout"]:::capture
        C4b -->|"No"| C6["Empty content"]:::output
        C1 -->|"No (stdout)"| C5
    end

    C4 --> Captured["capturedShadowOutput<br/>{format, parser, transport,<br/>host_path, container_path, content}"]:::output
    C5 --> Captured
    C6 --> Captured
```

---

## Result Persistence & Finding Extraction

### `persistStepResult` (`persistence.go`)

After each step completes, results are persisted in two layers:

#### Layer 1: Raw Scan Result

```mermaid
flowchart TD
    classDef layer fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef process fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    subgraph Layer1 ["Layer 1: Raw Scan Result"]
        R1["CreateScanResult"]:::layer --> R2["StepID, JobID, ProjectID, TargetID, ToolID"]:::layer
        R2 --> R3["RawData: JSON with full execution context<br/>(image, command, args, exit_code, stdout, stderr, shadow)"]:::layer
        R3 --> R4["ParsedData: JSON with parsing metadata<br/>(line_count, findings_count, parse_method)"]:::layer
        R4 --> R5["Severity: highest among findings"]:::layer
        R5 --> R6["Status: COMPLETED / FAILED"]:::layer
    end

    subgraph Layer2 ["Layer 2: Deduplicated Findings"]
        R6 --> F1["for each finding:"]:::process
        F1 --> F2["UpsertFinding"]:::process
        F2 --> F3["ProjectID, JobID, StepID, ToolID"]:::process
        F3 --> F4["Severity, Title, Host, Port"]:::process
        F4 --> F5["Fingerprint: parser-dependent SHA-256 key"]:::process
        F5 --> F6["Dedup by fingerprint (upsert)"]:::process
    end
```

### JSONL Shadow Persistence (`persistJSONLShadow`)

For `ClassStdoutJSONL` tools, persistence is streamlined:

1. **Raw Data**: All accumulated JSONL lines stored as-is
2. **Parsed Data**: Line count and parse metadata
3. **Findings**: Each JSONL line parsed as a finding (JSON object fields → title, host, port, severity)

### Finding Parsers (in order of attempt)

```mermaid
flowchart TD
    classDef start fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef result fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#000
    classDef endnode fill:#e0e0e0,stroke:#424242,stroke-width:2px,color:#000

    Start["parseFindingsFromOutput"]:::start --> CheckParser{"parser type?"}:::decision

    CheckParser -->|"xml"| TryXML["tryParseXML<br/>nmap XML parsing"]:::process
    TryXML --> XMLCheck{"Parsed OK?"}:::decision
    XMLCheck -->|"Yes"| XMLResult["Extracts: hostname, open ports,<br/>service name/product/version<br/>Title: 'Apache httpd 2.4.7 on port 80'<br/>Fingerprint: SHA-256 tool|host|port|title"]:::result
    XMLCheck -->|"No"| TryJSON

    CheckParser -->|"json/jsonl"| TryJSON
    CheckParser -->|"raw/lines"| Fallback
    CheckParser -->|"empty"| TryJSON

    TryJSON --> StartsBracket{"Starts with '['?"}:::decision
    StartsBracket -->|"Yes"| TryArray["tryParseJSONArray<br/>[{title, severity, ...}]"]:::process
    TryArray --> ArrayCheck{"Parsed OK?"}:::decision
    ArrayCheck -->|"Yes"| ArrayResult["Each item → parsedFinding"]:::result
    ArrayCheck -->|"No"| TryObject

    StartsBracket -->|"No"| TryObject{"Starts with '{'?"}:::decision
    TryObject -->|"Yes"| TryWrapper["tryParseJSONObject<br/>{findings/results/vulnerabilities: [...]}"]:::process
    TryWrapper --> WrapperCheck{"Found array in wrapper?"}:::decision
    WrapperCheck -->|"Yes"| WrapperResult["Each item → parsedFinding"]:::result
    WrapperCheck -->|"No"| Fallback
    TryObject -->|"No"| Fallback

    Fallback["Fallback: line-by-line"]:::process --> LineLoop["Each non-empty line → one finding<br/>title = line, host/port parsed if possible"]:::process
    LineLoop --> LineResult["findings from lines"]:::result

    XMLResult --> Done([parsedFindings]):::endnode
    ArrayResult --> Done
    WrapperResult --> Done
    LineResult --> Done
```

### Severity Normalization

```mermaid
flowchart LR
    classDef severity fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef level fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    Crit["critical / crit"]:::severity --> CRITICAL["CRITICAL"]:::level
    High["high / h"]:::severity --> HIGH["HIGH"]:::level
    Med["medium / med / moderate"]:::severity --> MEDIUM["MEDIUM"]:::level
    Low["low / l"]:::severity --> LOW["LOW"]:::level
    Other["anything else"]:::severity --> INFO["INFO"]:::level
```

Note: `persistStepResult` is only called for executed steps. Steps marked `SKIPPED` are not written to `scan_results`.

---

## Idempotency Mechanism

### Purpose

Prevent duplicate scan submissions when clients retry (network issues, timeouts).

### How It Works

```mermaid
flowchart TD
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef endnode fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    Start["idempotencyHashForRequest(req)"]:::process --> Clone["Clone the request"]:::process
    Clone --> Clear["Clear retry fields:<br/>idempotency_key, job_id, step_id, requested_at"]:::process
    Clear --> Marshal["Marshal with deterministic protobuf encoding"]:::process
    Marshal --> SHA["SHA-256 → hex string"]:::process
    SHA --> Done([Hash returned]):::endnode
```

### Cache Behavior

| Scenario                                  | Response                                                                                      |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| Key not found                             | Register, proceed normally                                                                    |
| Key found + hash matches + response ready | Replay cached response, `IsIdempotentReplay=true`, `OriginalRequestId=original first step_id` |
| Key found + hash matches + still running  | Return `Aborted` — retry shortly                                                              |
| Key found + hash differs                  | Return `AlreadyExists` — key reused with different payload                                    |
| TTL (24h) expired                         | Entry auto-removed by background cleanup                                                      |

---

## Policy & Security Deny List

### Policy Validation Flow

```mermaid
flowchart TD
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef blocked fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef allowed fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    Start["isBlocked(flag)"]:::process --> Normalize["Normalize flag:<br/>strip =, lowercase long flags,<br/>preserve case for short flags"]:::process
    Normalize --> CheckGlobal{"In globalDeniedSet?"}:::decision
    CheckGlobal -->|"Yes"| GlobalBlock["Blocked: 'globally denied'"]:::blocked
    CheckGlobal -->|"No"| CheckTool{"In tool deniedOptions?"}:::decision
    CheckTool -->|"Yes"| ToolBlock["Blocked: 'denied for tool X'"]:::blocked
    CheckTool -->|"No"| Allowed["Allowed ✓"]:::allowed

    GlobalBlock --> Result([Return error]):::blocked
    ToolBlock --> Result
    Allowed --> ResultOK([Continue]):::allowed
```

### Global Denied Flags (blocked for ALL tools)

```
Interactive:  -it, --interactive, --tty, -t, -i
Code exec:    --eval, --execute, --run, -e
Output redirect: --output, -o, --log, --logfile, --log-file
Debug/proxy:  --debug, --trace, --proxy, --upstream-proxy
```

### Per-Tool Denied Flags

Additional flags blocked per tool (stored in `tools.denied_options` column).

### Validation Flow

```
isBlocked(flag):
  1. Normalize flag (strip =, lowercase long flags, preserve case for short flags)
  2. Check globalDeniedSet
  3. Check tool-specific denied set
  4. If blocked → return error with reason ("globally denied" or "denied for tool X")
```

### Applied To

- Custom flags from user request
- Input schema field flags
- Scan config option flags

### Safe Flag Pattern

Custom flags must match: `^--?[A-Za-z0-9][A-Za-z0-9._-]*$`

---

## Runtime Configuration (gVisor / Network / Capabilities)

### Resolution Order

```mermaid
flowchart TD
    classDef default_node fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef blocked fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef success fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    subgraph GVisor ["useGVisor"]
        G1["Default: true"]:::default_node --> G2{"scanConfig.runtime.use_gvisor set?"}:::decision
        G2 -->|"Yes"| G3["Override with per-tool value"]:::default_node
        G2 -->|"No"| G4["Keep default: true"]:::success
    end

    subgraph Network ["networkMode"]
        N1{"executionConfig.network_policy.mode set?"}:::decision -->|"Yes"| N2["WINS — per-request"]:::success
        N1 -->|"No"| N3{"scanConfig.runtime.network_mode set?"}:::decision
        N3 -->|"Yes"| N4["Fallback — per-tool"]:::default_node
        N3 -->|"No"| N5["Default: bridge"]:::success
    end

    subgraph Privileged ["privileged"]
        P1["Default: false"]:::default_node --> P2{"scanConfig.runtime.privileged set?"}:::decision
        P2 -->|"Yes, true"| P3["BLOCKED: privileged forbidden"]:::blocked
        P2 -->|"No"| P4["Keep default: false"]:::success
    end

    subgraph Capabilities ["capAdd"]
        C1["scanConfig.runtime.cap_add"]:::default_node --> C2["Normalize: uppercase, strip CAP_ prefix"]:::default_node
        C2 --> C3{"In allowedRuntimeCapabilities?"}:::decision
        C3 -->|"Yes"| C4["Add to capAdd list"]:::success
        C3 -->|"No"| C5["BLOCKED: capability forbidden"]:::blocked
    end
```

### Allowed Runtime Capabilities

Only `NET_RAW` is permitted. All other capabilities are forbidden.

### Docker RunConfig

```
ToolConfig {
    Image:           plan.ImageRef
    Command:         plan.Command
    Args:            plan.Args
    Files:           pipelineFiles (injected list files)
    Volumes:         preparedShadow.Volumes (shadow output mounts)
    ImagePullPolicy: imagePullPolicyFromSource(source)  ← "custom"/"local"=never, else=if-missing
    Timeout:         request timeout or 5min default
    UseGVisor:       resolved
    NetworkMode:     resolved
    Privileged:      false (always forbidden)
    CapAdd:          resolved (only NET_RAW allowed)
    MemoryLimit:     from request resource limits
    CPUQuota:        from request resource limits
    OnLog:           callback → publishLog()
}
```

### Security Constraints

| Constraint      | Policy                                          |
| --------------- | ----------------------------------------------- |
| Host networking | **Forbidden** — returns error                   |
| Privileged mode | **Forbidden** — returns error                   |
| Capabilities    | **Allowlist** — only `NET_RAW`                  |
| gVisor runtime  | **Default: enabled** (can be disabled per-tool) |
| Network mode    | **Default: bridge** (can be overridden)         |

---

## Status Tracking & Job Lifecycle

### Step Status Transitions

```mermaid
stateDiagram-v2
    [*] --> PENDING
    PENDING --> QUEUED
    QUEUED --> RUNNING
    RUNNING --> COMPLETED
    RUNNING --> FAILED
    RUNNING --> SKIPPED
    COMPLETED --> [*]
    FAILED --> [*]
    SKIPPED --> [*]

    classDef pending fill:#e3f2fd,stroke:#1565c0,color:#000
    classDef queued fill:#fff3e0,stroke:#e65100,color:#000
    classDef running fill:#f3e5f5,stroke:#7b1fa2,color:#000
    classDef completed fill:#e8f5e9,stroke:#2e7d32,color:#000
    classDef failed fill:#ffebee,stroke:#c62828,color:#000
    classDef skipped fill:#f5f5f5,stroke:#616161,color:#000

    class PENDING pending
    class QUEUED queued
    class RUNNING running
    class COMPLETED completed
    class FAILED failed
    class SKIPPED skipped
```

`QUEUED` is maintained in the in-memory/runtime view and returned by `SubmitScan` / runtime snapshots. When status is synced to the DB, `QUEUED` is stored as `pending`. There is currently no active cancellation path in this module.

### Job Status Derivation

```mermaid
flowchart TD
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef status fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    Start["deriveJobStatus(completed, failed, pending)"]:::process --> C1{"failed > 0 AND completed > 0?"}:::decision
    C1 -->|"Yes"| PARTIAL["PARTIAL"]:::status
    C1 -->|"No"| C2{"failed > 0 AND pending == 0?"}:::decision
    C2 -->|"Yes"| FAILED["FAILED"]:::status
    C2 -->|"No"| C3{"completed > 0 AND pending == 0 AND failed == 0?"}:::decision
    C3 -->|"Yes"| COMPLETED["COMPLETED"]:::status
    C3 -->|"No"| C4{"pending > 0?"}:::decision
    C4 -->|"Yes"| RUNNING["RUNNING"]:::status
    C4 -->|"No"| PENDING["PENDING"]:::status
```

### Dual-Source Status Queries

`GetStepStatus` and `GetJobStatus` use a **dual-source strategy**:

```mermaid
flowchart TD
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef realtime fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef persistent fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef endnode fill:#e0e0e0,stroke:#424242,stroke-width:2px,color:#000

    Start["GetStepStatus / GetJobStatus"]:::process --> CheckMem{"In-memory runtime state?"}:::decision
    CheckMem -->|"Found"| Snapshot["Return runtime snapshot<br/>Real-time status for active scans"]:::realtime
    CheckMem -->|"Not found"| DBQuery["Query database<br/>scan_steps + scan_results"]:::persistent
    DBQuery --> Persistent["Return persistent status<br/>Completed scans / after restart"]:::persistent
    Snapshot --> Done([Response]):::endnode
    Persistent --> Done
```

### DB Sync Strategy

- **markStepRunning**: Sync immediately (fire-and-forget, error logged but doesn't block)
- **Terminal status**: Sync on step completion/failure
- **Job status**: Sync on every step status change via `syncJobStatusToDB`

When syncing job state to PostgreSQL, protobuf-only states such as `PARTIAL` and `CANCELLED` currently collapse to `failed` because the DB enum does not include those values.

---

## Background Cleanup

Runs every **5 minutes** via `startBackgroundCleanup`:

```mermaid
flowchart TD
    classDef start fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef delete fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef endnode fill:#e0e0e0,stroke:#424242,stroke-width:2px,color:#000

    Start(["Ticker: every 5 minutes"]):::start --> Loop1["For each idempotency entry"]:::process
    Loop1 --> AgeCheck{"age > 24h?"}:::decision
    AgeCheck -->|"Yes"| DelIdem["Delete entry"]:::delete
    AgeCheck -->|"No"| Loop2

    DelIdem --> Loop2["For each job"]:::process
    Loop2 --> TermCheck{"Terminal status AND<br/>finished > 1h ago?"}:::decision
    TermCheck -->|"Yes"| DelJob["Delete job from memory"]:::delete
    TermCheck -->|"No"| Loop3

    DelJob --> Loop3["For each step"]:::process
    Loop3 --> TermCheck2{"Terminal status AND<br/>finished > 1h ago?"}:::decision
    TermCheck2 -->|"Yes"| DelStep["Delete step from memory"]:::delete
    TermCheck2 -->|"No"| End([Done]):::endnode

    DelStep --> End
```

This prevents unbounded memory growth for long-running server instances. Note: DB records are **never** cleaned up by this process — they are permanent.

---

## End-to-End Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant Server as advancedScanServer
    participant Queue as Redis Queue
    participant Worker as Queue Worker
    participant DB as PostgreSQL
    participant Redis as Redis Pub/Sub
    participant Docker

    Client->>Server: SubmitScan
    Server->>DB: parseUnixCommand (resolve tools)
    DB-->>Server: tool configs
    Server->>Server: idempotencyHash + check cache
    Server->>DB: CREATE target (if needed)
    Server->>DB: INSERT scan_job
    Server->>DB: INSERT scan_steps (×N)
    Server->>Queue: EnqueueWithCapacityCheck

    alt Queue Full
        Server-->>Client: SubmitScanResponse (status=QUEUE_FULL)
    else Enqueued
        Server-->>Client: SubmitScanResponse (status=QUEUED)

        Note over Queue,Worker: Background execution
        Queue->>Worker: Dequeue job
        Worker->>DB: Re-resolve tools
        Worker->>Worker: Reconstruct chain spec
        Worker->>Worker: executeStepChain

        loop For each step
            Worker->>DB: UPDATE step → RUNNING
            Worker->>Worker: preparePipelineInput
            Worker->>Worker: buildAdvancedInvocation
            Worker->>Worker: prepareShadowOutput

            alt ClassStdoutJSONL
                Worker->>Docker: Run container (streamed)
                Docker-->>Worker: OnStdoutLine (real-time)
                Worker->>Redis: PUBLISH fan-out (SSE + shadow + pipe)
            else ClassFileOnly
                Worker->>Docker: Run container (standard)
                Docker-->>Worker: OnLog (stdout/stderr)
                Worker->>Redis: PUBLISH log lines
                Worker->>Worker: captureShadowOutput (post-run)
            end

            Worker->>Worker: writeShadowArtifact
            Worker->>DB: INSERT scan_result
            Worker->>DB: UPSERT findings
            Worker->>DB: UPDATE step status
            Worker->>DB: UPDATE job status
            Worker->>Worker: extractPipelineOutputs
        end

        Worker->>Queue: Complete(receipt)
    end

    Client->>Server: GetJobStatus
    Server->>Server: runtimeJobStatusSnapshot
    Server-->>Client: JobStatusResponse

    Client->>Server: GetResults
    Server->>DB: SELECT findings
    Server-->>Client: GetResultsResponse
```

---

## Configuration Environment Variables

| Variable                | Default          | Purpose                                |
| ----------------------- | ---------------- | -------------------------------------- |
| `REDIS_ADDR`            | `localhost:6379` | Redis server address                   |
| `REDIS_SCAN_LOG_PREFIX` | `scan:logs`      | Redis Pub/Sub channel prefix           |
| `SHADOW_OUTPUT_ROOT`    | `/tmp/shadow`    | Default directory for shadow artifacts |
