# ADK + Pydantic AI 10-case framework litmus — scanner reveal

- Scanner code base: `36c48f88da2106c367e3a96e2f94432e8ef595ca`
- Scanned: 10/10
- Findings: 62
- Attack paths: 9

| Case | Framework | Repository | Scan | Agents | Tools | MCP | Flows | Findings | Paths |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| rw-009 | google-adk | vivekcommit/Cloud_Architecture_Review | ok | 11 | 26 | 2 | 0 | 3 | 1 |
| rw-017 | google-adk | mxyhi/always-on-memory-agent | ok | 4 | 9 | 0 | 0 | 11 | 2 |
| rw-004 | google-adk | JoanMarinPages/agentGemini | ok | 2 | 18 | 0 | 0 | 13 | 0 |
| rw-007 | google-adk | joshnaim1/ocr-test | ok | 1 | 2 | 0 | 0 | 2 | 1 |
| rw-012 | google-adk | namanraina16/morning-wire | ok | 1 | 1 | 0 | 0 | 0 | 0 |
| rw-155 | pydantic-ai | shotgun-sh/shotgun | ok | 9 | 37 | 0 | 0 | 23 | 0 |
| rw-152 | pydantic-ai | kumarvipu1/agentic-ppt-slide | ok | 3 | 10 | 0 | 3 | 7 | 3 |
| rw-147 | pydantic-ai | hope-tatenda-mutema/Pedantic-AI-Deep-Research-Agent | ok | 1 | 4 | 0 | 0 | 0 | 0 |
| rw-150 | pydantic-ai | Amar-Ag/project-ideation-tool | ok | 1 | 2 | 0 | 0 | 2 | 1 |
| rw-164 | pydantic-ai | amscotti/local-LLM-with-RAG | ok | 1 | 1 | 0 | 0 | 1 | 1 |

## Finding detail

### rw-009 — vivekcommit/Cloud_Architecture_Review

- **NET002 medium** — Outbound capability has no destination constraint — agent=cloud_architecture_review_orchestrator — agent.py:95
  - capabilities=network.external
- **NET002 medium** — Outbound capability has no destination constraint — agent=iac_ingestion_agent — agents/iac_ingestion_agent.py:5
  - capabilities=network.external
  - authority_relationship=authority-v1:f04c5facb2ba6ddf266d
- **PATH009 medium** — Potential untrusted-input path through delegated agent to unconstrained egress — agent=cloud_architecture_review_orchestrator — agents/iac_ingestion_agent.py:16
  - user-or-remote-input -> cloud_architecture_review_orchestrator -> delegate:iac_ingestion_agent -> fetch_iac_files -> unrestricted external destination

### rw-017 — mxyhi/always-on-memory-agent

- **PATH002 high** — Potential untrusted-input path to state-changing action — agent=memory_orchestrator — agent.py:505
  - agent.handle_query:external-input -> memory_orchestrator -> delegate:ingest_agent -> data.write
- **PATH002 high** — Potential untrusted-input path to state-changing action — agent=memory_orchestrator — agent.py:505
  - agent.handle_query:external-input -> memory_orchestrator -> delegate:consolidate_agent -> data.write
- **ADK001 medium** — Privileged ADK agent has no detected tool-control callback/plugin — agent=consolidate_agent — agent.py:472
  - privileged_tools=store_consolidation
- **ADK001 medium** — Privileged ADK agent has no detected tool-control callback/plugin — agent=ingest_agent — agent.py:449
  - privileged_tools=store_memory
- **ADK001 medium** — Privileged ADK agent has no detected tool-control callback/plugin — agent=memory_orchestrator — agent.py:505
  - privileged_tools=delegate:ingest_agent,delegate:consolidate_agent
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=consolidate_agent — agent.py:300
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:720e8dc4160b4f87a71b
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=ingest_agent — agent.py:227
  - capabilities=data.write
  - authority_relationship=authority-v1:0f73b39b7e866b2c85d9
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=memory_orchestrator — agent.py:505
  - capabilities=agent.delegate,data.write
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=memory_orchestrator — agent.py:505
  - capabilities=agent.delegate,data.read,data.write
- **CAP005 medium** — Combined read and write authority — agent=consolidate_agent — agent.py:472
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:586a4241c0205ebf1da4
  - authority_relationship=authority-v1:720e8dc4160b4f87a71b
- **CAP005 medium** — Combined read and write authority — agent=memory_orchestrator — agent.py:505
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:703ffc7fc87f8c0941fe

### rw-004 — JoanMarinPages/agentGemini

- **ADK001 medium** — Privileged ADK agent has no detected tool-control callback/plugin — agent=AgroAsesorIA — agentGemini/agent.py:38
  - privileged_tools=process_checkout,schedule_service,generate_discount_code
- **ADK001 medium** — Privileged ADK agent has no detected tool-control callback/plugin — agent=FunnelAgent — agent.py:98
  - privileged_tools=get_or_create_user_profile_from_firestore_tool,update_user_profile_in_firestore_tool,add_to_products_a_repasar_in_firestore_tool,request_video_upload_link_tool,prepare_selection_update_for_session_state
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=AgroAsesorIA — agentGemini/tools/conversion_tools.py:20
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:9e649119ffaa0e608456
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=AgroAsesorIA — agentGemini/tools/conversion_tools.py:149
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:83f40afc384e8729084c
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=AgroAsesorIA — agentGemini/tools/conversion_tools.py:273
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:2bacaf3f9f3f36c97d41
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=FunnelAgent — agent.py:104
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:bcc1cc02bf5af6c558f8
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=FunnelAgent — agent.py:105
  - capabilities=data.write
  - authority_relationship=authority-v1:d3bbdf2c7f64a9f31137
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=FunnelAgent — agent.py:114
  - capabilities=data.write
  - authority_relationship=authority-v1:2cd9d8d8d1ae09f3a2d6
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=FunnelAgent — agent.py:115
  - capabilities=external.write,network.external
  - authority_relationship=authority-v1:450e4c2c16525528f81a
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=FunnelAgent — agent.py:116
  - capabilities=data.write
  - authority_relationship=authority-v1:5fa1594cd719e79f5d42
  - approval_resolution=unknown
- **CAP005 medium** — Combined read and write authority — agent=AgroAsesorIA — agentGemini/agent.py:38
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:2bacaf3f9f3f36c97d41
  - authority_relationship=authority-v1:83f40afc384e8729084c
- **CAP005 medium** — Combined read and write authority — agent=FunnelAgent — agent.py:98
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:2cd9d8d8d1ae09f3a2d6
  - authority_relationship=authority-v1:37dddeb2b156927723f9
- **NET002 medium** — Outbound capability has no destination constraint — agent=FunnelAgent — agent.py:98
  - capabilities=external.write,network.external
  - authority_relationship=authority-v1:450e4c2c16525528f81a

### rw-007 — joshnaim1/ocr-test

- **DATA001 high** — Broad resource scope — agent=document_processing_agent — agent.py:15
  - resources=*
- **PATH010 high** — Potential untrusted-input local file read to external service — agent=document_processing_agent — tools/document_ocr.py:52
  - user-or-remote-input -> document_processing_agent -> process_document_with_ocr -> model-selected local file -> process_document

### rw-012 — namanraina16/morning-wire

- No scanner findings.

### rw-155 — shotgun-sh/shotgun

- **AGT020 high** — Shell or process execution without approval — agent=agent — src/shotgun/agents/common.py:345
  - capability=process.execute
  - approval=None
- **AGT020 high** — Shell or process execution without approval — agent=agent — test/integration/codebase/tools/conftest.py:280
  - capability=process.execute
  - approval=None
- **AGT021 high** — Destructive action without human approval — agent=agent — src/shotgun/agents/common.py:333
  - capability=destructive.write
  - approval=None
- **AGT021 high** — Destructive action without human approval — agent=agent — src/shotgun/agents/router/router.py:151
  - capability=destructive.write
  - approval=None
- **AGT022 medium** — State-changing tool without approval — agent=agent — src/shotgun/agents/common.py:328
  - capability=data.write
  - approval=None
- **AGT022 medium** — State-changing tool without approval — agent=agent — src/shotgun/agents/common.py:329
  - capability=data.write
  - approval=None
- **AGT022 medium** — State-changing tool without approval — agent=agent — src/shotgun/agents/common.py:332
  - capability=data.write
  - approval=None
- **AGT022 medium** — State-changing tool without approval — agent=agent — src/shotgun/agents/router/router.py:148
  - capability=data.write
  - approval=None
- **AGT022 medium** — State-changing tool without approval — agent=agent — src/shotgun/agents/router/router.py:150
  - capability=data.write
  - approval=None
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/common.py:328
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:67083c780daf9d1d94ea
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/common.py:329
  - capabilities=data.read,data.write
  - authority_relationship=authority-v1:7eb1986f599486f620bd
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/common.py:332
  - capabilities=data.write
  - authority_relationship=authority-v1:a64d89cbf83b93a735dc
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/common.py:333
  - capabilities=destructive.write
  - authority_relationship=authority-v1:6fd494073445bed7a811
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/common.py:345
  - capabilities=process.execute
  - authority_relationship=authority-v1:c10d27ed99be8fdbd183
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/router/router.py:148
  - capabilities=data.write
  - authority_relationship=authority-v1:3d1be7c7162ff73cedea
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/router/router.py:150
  - capabilities=data.write
  - authority_relationship=authority-v1:ba3ec9dc088803424571
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — src/shotgun/agents/router/router.py:151
  - capabilities=destructive.write
  - authority_relationship=authority-v1:acf0bac049ad21cb3bac
  - approval_resolution=unknown
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=agent — test/integration/codebase/tools/conftest.py:280
  - capabilities=process.execute
  - authority_relationship=authority-v1:c10d27ed99be8fdbd183
  - approval_resolution=unknown
- **CAP005 medium** — Combined read and write authority — agent=agent — src/shotgun/agents/autopilot/stage_monitor.py:88
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:043831dbf8c06dce200d
  - authority_relationship=authority-v1:236d9536fb546c96e4b9
- **CAP005 medium** — Combined read and write authority — agent=agent — src/shotgun/agents/common.py:308
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:043831dbf8c06dce200d
  - authority_relationship=authority-v1:236d9536fb546c96e4b9
- **CAP005 medium** — Combined read and write authority — agent=agent — src/shotgun/agents/file_read.py:103
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:043831dbf8c06dce200d
  - authority_relationship=authority-v1:236d9536fb546c96e4b9
- **CAP005 medium** — Combined read and write authority — agent=agent — src/shotgun/agents/router/router.py:135
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:043831dbf8c06dce200d
  - authority_relationship=authority-v1:236d9536fb546c96e4b9
- **CAP005 medium** — Combined read and write authority — agent=agent — test/integration/codebase/tools/conftest.py:269
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:043831dbf8c06dce200d
  - authority_relationship=authority-v1:236d9536fb546c96e4b9

### rw-152 — kumarvipu1/agentic-ppt-slide

- **PATH001 critical** — Potential untrusted-input path to command execution — agent=presentation_agent — agent_tools.py:229
  - generate_powerpoint_slides.code -> agent_tools.generate_powerpoint_slides -> compile
  - flow_id=flow-v1:d6c9ce10d883ce62fdd3947d
- **PATH001 critical** — Potential untrusted-input path to command execution — agent=slide_agent — agent_tools.py:196
  - python_execution_tool.code -> agent_tools.python_execution_tool -> compile
  - flow_id=flow-v1:8546180fe8d77ef2d2d543d5
- **PATH001 critical** — Potential untrusted-input path to command execution — agent=slide_agent — agent_tools.py:166
  - graph_generator.code -> agent_tools.graph_generator -> compile
  - flow_id=flow-v1:b5f700ff90f3542e28a7d60f
- **AGT022 medium** — State-changing tool without approval — agent=slide_agent — agent.py:114
  - capability=data.write
  - approval=None
- **AGT040 medium** — Privileged tool lacks explicit guardrail or approval — agent=slide_agent — agent.py:114
  - capabilities=data.write
  - authority_relationship=authority-v1:e9f6352a26add298775e
  - approval_resolution=unknown
- **CAP005 medium** — Combined read and write authority — agent=slide_agent — agent.py:109
  - data.read
  - data.write/destructive.write
  - authority_relationship=authority-v1:077feaf1acc4995067b4
  - authority_relationship=authority-v1:b4ef933f9b2dd63587d8
- **NET002 medium** — Outbound capability has no destination constraint — agent=slide_agent — agent.py:109
  - capabilities=network.external
  - authority_relationship=authority-v1:b4ef933f9b2dd63587d8
  - authority_relationship=authority-v1:f26d357010da7a8228df

### rw-147 — hope-tatenda-mutema/Pedantic-AI-Deep-Research-Agent

- No scanner findings.

### rw-150 — Amar-Ag/project-ideation-tool

- **NET001 high** — Outbound reachability lacks a detected restriction — agent=agent — src/agent.py:360
  - destinations=<dynamic-url>
- **PATH011 high** — Potential untrusted-input path to server-side URL fetch — agent=agent — src/agent.py:425
  - app.get_bot_response:streamlit-input -> agent -> fetch_curriculum -> model-selected URL -> <dynamic-url>

### rw-164 — amscotti/local-LLM-with-RAG

- **PATH013 high** — Potential user-selected server directory exposure through RAG — agent=self.agent — interfaces/streamlit_app.py:115
  - streamlit_app:documents-folder -> recursive server-side file ingestion -> RAG index -> self.agent -> search_documents -> indexed file content in agent response

