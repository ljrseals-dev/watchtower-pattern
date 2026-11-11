# The Trust Boundary You Forgot You Had: Threats Posed by AI-Coded Plugins and DAW Workstations, and a Human-in-the-Loop Architecture for Stopping Them

**Authors:** Lewis James Seals Jr. and Angela La’Vette Seals

## Abstract

Digital audio workstations (DAWs) and the plugin ecosystems that surround them have undergone a structural transformation. What was once a relatively contained world of native C++ audio processors and curated installer packages has become an open, agentic, and increasingly automated software supply chain. AI coding agents now generate plugin binaries, large language models drive DAW sessions through the Model Context Protocol (MCP), and “vibe-coded” effects and instruments are distributed through the same registries, forums, and repositories that musicians have learned to trust. This paper argues that the resulting threat surface is not a marginal extension of conventional endpoint security. It is a distinct class of risk in which the plugin folder becomes an executable trust boundary, the AI agent becomes an unconfined write primitive, and the music project becomes a target for data integrity attacks that leave no obvious forensic trace. We document the empirical record: the Zrythm repository compromise, the Phantom-Audio MCP path-traversal and decompression-bomb vulnerabilities, the Suno data breach affecting 55.3 million accounts, the DinDoor campaign impersonating Ableton Live and Kontakt installers, the GlassWorm self-spreading developer-extension malware, and the “Mental Damage” caption-poisoning attack on retrieval-augmented text-to-music systems. We then propose a defensive architecture grounded in the Watchtower Pattern, a detection-and-review system that observes, scores, explains, and queues findings while reserving every consequential action for a human reviewer. We extend the Watchtower threat model to the music-production domain and specify concrete detection rules for MCP output-path confinement, audio decompression amplification, caption-integrity monitoring, unpinned package installation, and unauthenticated control endpoints. The paper concludes that the correct response to AI-coded plugin risk is not the abolition of AI assistance but the deliberate reconstruction of trust boundaries around the DAW workstation, enforced through advisory detection rather than automatic enforcement, because an automated enforcement system in a creative environment will eventually destroy a session, a project, or a career, and no advisory tier that fires an action is advisory at all.

---

## 1. Introduction

The modern music-production workstation is a general-purpose computer running a real-time operating system scheduling discipline, a large collection of third-party executable code, and an increasingly persistent network connection. The DAW itself—Ableton Live, Logic Pro, REAPER, FL Studio, Cubase, Studio One, Ardour, Zrythm—is the host process. The plugins—VST3, AU, AAX, CLAP, JSFX—are dynamically loaded modules that execute inside that host process with the full privileges of the logged-in user. This architectural fact is not new. What is new is the velocity and opacity with which executable code now arrives in the plugin folder, and the degree to which that code is generated, modified, and orchestrated by artificial intelligence.

Three developments have converged. First, AI coding agents have made it trivial to produce compiling audio DSP code. A current model will write a gain, delay, filter, or saturator in a minute, and the resulting plugin is real. The “vibe coding” workflow—describe an effect, let an agent write the C++, build the result—has moved from experiment to routine practice, and the distribution of those binaries has followed. Second, the Model Context Protocol has given large language models a standardized interface to local tools, files, and DAW sessions. MCP servers now expose Ableton Live’s object model, REAPER’s scripting bridge, and audio-rendering pipelines to any compatible AI client. Third, the commercial and open-source software supply chains that feed the music ecosystem have been repeatedly compromised, and the attackers have learned that music producers are a high-value, low-defended population with valuable intellectual property, valuable credentials, and a professional culture that prizes workflow continuity over security hygiene.

The result is a threat landscape that cannot be addressed by antivirus signatures alone. A VST3 is not inert media; it is executable code that the DAW loads, initializes, and runs. A plugin folder is not passive storage; it contains programs that the music software may execute, including during the scan process itself. An MCP tool call is not a harmless configuration change; when the output path is unconfined, it is an arbitrary file-write primitive that can overwrite ~/.zshrc or a REAPER __startup.lua and achieve local code execution on the next shell invocation or DAW launch. A highly compressed FLAC file is not just a small download; in an ingestion pipeline without duration or frame-count validation, it can expand into a multi-gigabyte PCM buffer and exhaust workstation memory. And a retrieved music caption is not a neutral description; in a retrieval-augmented text-to-music system, a small number of poisoned captions can steer generation toward an attacker-chosen target without modifying the user prompt, the retriever, or the generator.

This paper makes four contributions. First, it synthesizes the empirical record of AI-coded plugin and DAW-workstation threats into a coherent taxonomy, distinguishing supply-chain compromise, agentic tool-boundary violation, resource-exhaustion attacks, data-integrity attacks, and credential and identity theft. Second, it analyzes the structural reasons why the DAW environment is particularly exposed: in-process plugin execution, broad filesystem permissions, weak installer verification, project-file value, and the cultural normalization of downloading executables from semi-trusted sources. Third, it presents the Watchtower Pattern as a defensible architectural response and specifies how its threat model and detection rules must be extended for music-production environments. Fourth, it proposes a set of concrete, testable detection rules—MCP output-path confinement, decompression amplification thresholds, caption-poisoning indicators, unpinned-install detection, and unauthenticated-endpoint exposure—that can be implemented in a stdlib-only harness without turning the security tool into a surveillance tool or an automated destroyer of creative work.

The paper is organized as follows. Section 2 establishes the technical background: how plugins execute, how MCP exposes DAW control, and how AI coding agents enter the plugin supply chain. Section 3 presents the threat taxonomy with case studies. Section 4 analyzes the structural vulnerabilities of the DAW workstation. Section 5 introduces the Watchtower Pattern and its design constraints. Section 6 specifies domain-specific detection rules and a patch prompt for extending the Watchtower harness. Section 7 discusses governance, legal, and operational considerations. Section 8 addresses honest gaps and failure modes. Section 9 concludes.

---

## 2. Technical Background

### 2.1 The Plugin as Executable Code

The VST3 specification describes a plugin module as executable software. On Windows, the module contains a DLL; on macOS, it is a bundle containing a Mach-O binary. A host such as Ableton Live discovers those modules, initializes them, and loads their components when needed. This is not a defect in VST3; it is the fundamental design that makes low-latency audio processing possible. A plugin that could not execute native code would not be able to implement a real-time convolution reverb or a virtual-analog oscillator with acceptable performance.

The security consequence is that every plugin is a potential code-execution vector. In February 2024, a researcher publishing as infosecnoodle demonstrated the point using Steinberg’s own Hello World VST3 example on Windows. The researcher added a system call, rebuilt the plugin, and placed it in the standard VST3 location. Opening the modified plugin in Ableton executed the added command. The researcher also showed that when Ableton detected a new or modified VST in the plugin directory, plugin initialization could execute code during the scan process; the execution appeared under the Ableton Index process. For persistence, the researcher injected code into AbletonPushCpl.exe, an Ableton-related process that could remain running after the DAW closed. This was not a vulnerability in Ableton or in VST3. It was a demonstration of what executable plugin code is capable of doing when a user chooses to load it.

The plugin folder, therefore, must be treated as a code-execution boundary, not as a media library. This distinction matters because the cultural practices surrounding plugin acquisition have not caught up with the technical reality. Producers routinely download free plugins from forums, install “cracked” versions of commercial products, and load preset packs that may contain embedded scripts or installers. The historical LoudMiner campaign, documented by ESET in June 2019, distributed a cryptocurrency miner inside pirated audio software for Windows and macOS, with lures carrying names such as Ableton Live, Reason, Sylenth1, Nexus, Reaktor, and Auto-Tune; one website alone listed 137 VST-related applications. The 2026 iteration of the same pattern is more intimate: security researchers documented a macOS loader disguised predominantly as cracked music software, with the same hidden configuration inside more than 100 malicious DMG files, including a lure parameter reading “Download iZotope Ozone Pro … Plugin Crack”.

### 2.2 The Model Context Protocol and DAW Control

The Model Context Protocol is a standardized interface that allows large language models to invoke local tools and access local resources. In the music-production context, MCP servers have been built for Ableton Live, REAPER, and general audio-processing pipelines. ableton-for-ai implements MCP to make Ableton projects “hearable and visible” to AI models. AbletonMCP connects Ableton Live to Claude, allowing prompt-assisted music production, track creation, and Live session manipulation. ReaperMCP provides AI-powered music production in REAPER through MCP and pairs with local AI music and vocal generation tools. ableton-mind exposes the full Live Object Model to LLMs with an embedded native device knowledge base and declarative music recipes.

The security significance of MCP is that it converts a natural-language model into a tool-calling agent with the ability to write files, render audio, modify project state, and in some configurations execute shell commands. The protocol itself is not inherently insecure, but its security depends entirely on the confinement of the tools it exposes. When an MCP tool accepts an arbitrary absolute output path, the agent driving that tool has an arbitrary file-write primitive. When an MCP server exposes a stem-separation or rendering tool that accepts compressed audio without duration limits, the agent has a memory-exhaustion primitive. When an MCP server exposes a control endpoint without authentication, any process that can reach the endpoint has a denial-of-service primitive.

The Phantom-Audio package illustrates the first two failures in a single advisory. In versions through 1.3.0, when the PHANTOM_OUTPUT_DIR environment variable was unset—which was the default—the MCP tools accepted arbitrary absolute output paths with no confinement. Anything able to send tool calls, including an AI agent driving the MCP interface, could write or overwrite arbitrary files the process user could write, including shell startup files such as ~/.zshrc or a REAPER __startup.lua, which is effectively local code execution on a developer workstation. Separately, the stem-separation and ingestion pipelines lacked validation controls during decompression, so a small, highly compressed FLAC or OGG file could expand into a multi-gigabyte PCM structure in workstation memory, causing a localized denial of service and increasing exposure to decoder bugs such as CVE-2026-37555 in libsndfile.

The Phantom-Audio advisory is not an isolated curiosity. It is a template. Any MCP server that exposes file-writing, rendering, or project-conversion tools without canonical path confinement and without resource limits is vulnerable to the same class of attack. The Acronis TRU Cyber Pulse 2026 report observes that exposed agent gateways can give attackers opportunities to reach commands, files, and credentials, and that threat actors are linking multiple AI models with attack tools and MCP servers to automate reconnaissance, exploitation, and infrastructure management. The music-production MCP ecosystem is a subset of this broader agent-gateway exposure, and it inherits the same risks.

### 2.3 AI Coding Agents in the Plugin Supply Chain

The third structural change is the entry of AI coding agents into the plugin supply chain itself. The “vibe coding” workflow begins with a natural-language description of an audio effect and ends with a compiled binary that the DAW can load. The code-generation step is fast, but the surrounding work—installing an IDE and build system, matching the plugin framework version to what the model learned, fixing build errors, testing real-time safety, code-signing and notarizing the binary, and maintaining it across OS and DAW updates—remains the responsibility of the human. The realistic timeline for a first working, shareable plugin is weeks, not an afternoon, and the weeks are not spent writing code.

The security problem is not that AI writes bad DSP code. The problem is that AI-generated code enters a distribution ecosystem with weak verification, and the agent itself can be manipulated. CVE-2026-30304 documents a design flaw in the AI Code VS Code extension: the extension offers a “execute safe commands” mode and an “execute all commands” mode, and the safe mode relies entirely on the language model’s judgment of whether a command is destructive. An attacker can employ a generic template to wrap any malicious command and mislead the model into misclassifying it as a safe command, bypassing the safety control and achieving remote command execution. The same pattern applies to any AI coding tool that uses model judgment as a security boundary. The boundary is not a boundary; it is a suggestion.

The supply chain around AI coding tools has also been targeted directly. The GlassWorm campaign, first observed in October 2025, used the OpenVSX registry and the Microsoft Visual Studio Marketplace to distribute malicious extensions, with later waves deploying more than 24 malicious extensions and then 73 “sleeper” extensions that appeared benign on upload before turning malicious through a subsequent update or runtime payload fetch. A Zig-compiled native dropper variant executed entirely outside the JavaScript runtime sandbox, acquiring full operating-system-level access on developer workstations and silently installing a second-stage malicious extension into each editor using the editor’s own command-line tooling. GlassWorm used the Solana blockchain as a command-and-control channel and stole credentials from npm, OpenVSX, and other developer accounts. For a music producer who also uses a code editor to customize plugins or scripts, the developer-tool supply chain and the music-production supply chain are the same supply chain.

---

## 3. Threat Taxonomy and Case Studies

### 3.1 Supply-Chain Compromise

Supply-chain compromise is the oldest and most consequential category. The attacker does not need to exploit a vulnerability in the DAW or the plugin; the attacker simply distributes a malicious update, installer, or dependency through a channel the user already trusts.

**The Zrythm repository hack (October 2025).** Zrythm, an open-source DAW, experienced a sophisticated supply-chain attack in which hackers injected malicious automation scripts into what appeared to be legitimate plugin updates, affecting over 15,000 music producers worldwide. Malicious code was hidden within automation preset files; attackers gained access to users’ project files and audio samples; ransomware encrypted entire music libraries and demanded Bitcoin payments; estimated damage was $2.3 million in lost projects and downtime. The Zrythm case is important because it demonstrates that the open-source transparency model does not automatically protect users who consume binaries or updates without verifying the build pipeline. The repository is visible, but the update channel is the attack surface.

**The Sound Radix breach (March 2026).** Sound Radix, an audio-production tools company, disclosed a data breach that exposed approximately 293,000 unique email addresses and names, with potentially hashed passwords, following unauthorized access to a customer support platform. The breach did not involve plugin code execution, but it illustrates the credential-harvesting value of plugin vendors. A plugin vendor holds customer identity data, license keys, and download entitlements. A breach at the vendor enables follow-on phishing, credential stuffing, and supply-chain impersonation.

**The DinDoor campaign (May 2026).** Attackers published counterfeit installers and plugins on GitHub and SourceForge impersonating popular software including ChatGPT, Claude, AutoTune, Kontakt, Ableton Live, and ZENOLOGY, delivering the Deno-based backdoor DinDoor. The operation was promoted through compromised YouTube channels posting AI-generated videos linking to malicious repositories; the videos drew more than 50,000 views before takedowns. The infection chain used malicious MSI installers or PowerShell-based loaders to install Scoop and WinGet, then deployed the Deno runtime to fetch and execute staged JavaScript payloads. DinDoor established persistence, profiled infected systems, and fetched additional malware including a Deno-based RAT capable of remote execution, data theft, screenshot capture, SOCKS5 proxying, and browser credential theft. It targeted Telegram, Discord, more than 50 crypto wallet extensions, and at least 10 crypto wallet applications, and used Microsoft Edge, the Chrome DevTools Protocol, and WebRTC to stream victim screens peer-to-peer while blending malicious traffic with legitimate browser activity. The campaign is a direct demonstration that the music-production audience is now a named target in commodity malware distribution.

**GlassWorm and the developer-extension supply chain (2025–2026).** GlassWorm is a self-spreading malware campaign that targeted the OpenVSX and Visual Studio Code extension registries, with estimated installs reaching 35,800 in the first wave and subsequent waves adding dozens of malicious extensions. The campaign matters to music production because the boundary between “developer tools” and “music tools” has collapsed. A producer who uses a code editor to write a REAPER script, customize a JSFX effect, or build a plugin from AI-generated code is exposed to the same registry poisoning that targets professional software developers.

**Unpinned dependency installation.** The Suno V5 music skill was reported to auto-install unpinned pip packages at startup, store API keys in browser local storage, and expose an unauthenticated /shutdown endpoint for denial of service. The unpinned installation is a supply-chain execution path: a compromised package index or a dependency-confusion attack can cause arbitrary code to execute at skill startup without any user action beyond launching the skill. This pattern is not unique to Suno; any AI skill or MCP server that installs dependencies at runtime without version pins or hash verification inherits the same risk.

### 3.2 Agentic Tool-Boundary Violation

Agentic tool-boundary violations occur when an AI agent is given a tool whose parameters are not confined, and the agent—whether through prompt injection, model error, or adversarial input—uses that tool to affect resources outside the intended scope.

**Phantom-Audio path traversal (GHSA-52vm-mxx8-f227).** The Phantom-Audio MCP server accepted arbitrary absolute output paths when PHANTOM_OUTPUT_DIR was unset. An AI agent driving the MCP interface could write or overwrite any file the process user could write, including ~/.zshrc or a REAPER __startup.lua, achieving local code execution on the next shell invocation or DAW launch. The root cause was the absence of path canonicalization and sandbox confinement: the server did not invoke os.path.realpath or verify that target paths resolved inside a dedicated sandbox directory, and it did not protect against time-of-check-to-time-of-use symlink swapping until version 1.3.1 added atomic writes with system-level descriptor options.

**Ableton MCP and indirect prompt injection.** MCP servers that expose DAW state to an LLM create an indirect prompt-injection surface. If the model ingests project data, track names, plugin metadata, or file paths that contain attacker-controlled text, that text can influence the model’s subsequent tool calls. A malicious project file or a compromised sample pack could contain instructions that cause the agent to render audio to an unexpected location, overwrite a project file, or invoke a destructive operation. The FL Studio scripting skill documentation explicitly warns that omission of safety guidance can lead an agent to perform destructive file operations without backups or confirmation, and that agent memory poisoning can write attacker-controlled rules into memory that affect later sessions.

**CVE-2026-30304 and the failure of model-judgment safety.** The AI Code extension’s “execute safe commands” mode is a case study in why model judgment cannot serve as a security boundary. The extension delegates the classification of a command as safe or destructive to the language model. An attacker wraps a malicious command in a template that causes the model to misclassify it as safe, and the safety control is bypassed. The lesson generalizes: any agentic system that uses an LLM to decide whether an action is permissible is vulnerable to prompt injection that targets that decision. The only robust boundary is one enforced by deterministic code outside the model.

### 3.3 Resource-Exhaustion and Decompression Amplification

Audio workloads are inherently memory-intensive, and audio decoders are complex parsers with a long history of memory-safety bugs. An attacker who can control the input to a decoder can often cause memory exhaustion or code execution.

**Phantom-Audio decompression bomb.** The Phantom-Audio ingestion engine handled compressed file streams such as OGG and FLAC for analysis. The decompression routines failed to validate logical boundaries, allowing small, highly compressed audio payloads to expand dynamically into multi-gigabyte structures in workstation memory. Compressed formats exploit frequency-domain modeling to compress uniform silence or repetitive synthetic audio patterns very efficiently; a few kilobytes of FLAC-encoded silence can expand to gigabytes of PCM data. The pipeline did not check overall duration, frame counts, or channel matrices before raw PCM expansion, causing immediate memory depletion.

**SGLang load_audio decompression amplification (CVE-2026-109226).** A related vulnerability in SGLang through version 0.5.21 allowed unauthenticated remote attackers to exhaust worker memory and CPU by submitting highly compressed audio decoded without duration or sample limits. Attackers could supply small FLAC-encoded silence files through audio_url or audio_data inputs that expand into massive PCM buffers. The pattern is identical: the decoder trusts metadata or accepts unbounded input, and the resulting allocation exceeds available memory.

**Decoder memory-corruption vulnerabilities.** Decompression amplification is not only a denial-of-service problem. It also increases exposure to decoder bugs. CVE-2026-37555 in libsndfile 1.2.2 is a critical integer overflow in the IMA ADPCM codec affecting AIFF and WAV file processing. When samplesperblock and blocks are both 50000, the 32-bit product overflows to a negative value before being assigned to a 64-bit frame count, leading to buffer overflow. The dr_flac integer overflow (CVE-2025-14369) and the dr_wav heap out-of-bounds write (CVE-2026-29022) are additional examples of audio decoder memory-safety failures that can be triggered by crafted files. A DAW or plugin that decodes untrusted audio inherits these risks.

### 3.4 Data-Integrity and Caption-Poisoning Attacks

The least visible and potentially most damaging category is data-integrity attack. In these attacks, the adversary does not steal data or execute code; the adversary changes what the system produces, often in ways that are difficult to detect because the output remains superficially plausible.

**“Mental Damage”: caption poisoning in retrieval-augmented text-to-music.** Retrieval-augmented text-to-music systems augment underspecified user prompts using captions retrieved from a music caption dataset. This design introduces an integrity dependency on the music knowledge database. Researchers showed that an attacker can poison the database by injecting a small number of crafted music captions, causing the system to retrieve malicious captions that bias prompt augmentation and steer generation away from the user’s intended function, without modifying the user prompt, the retriever, or the generator. The proposed dual-layer caption-poisoning strategy preserves high-level retrieval anchors while injecting low-level acoustic descriptors to steer prompt augmentation and downstream music generation toward an attacker-chosen target intent. In a MusicCaps knowledge database with a CLAP retriever and a MusicGen pipeline, poisoned generations moved substantially closer to the attacker’s target while remaining comparably aligned with the original user query.

The significance of this attack is that it defeats the intuitive security model. The user prompt is unchanged, the model weights are unchanged, and the retrieval mechanism is unchanged. The only changed component is the data the retriever draws from, and the output remains plausible. For a professional composer or sound designer, the consequence is not a crashed DAW but a deliverable that subtly violates creative intent, licensing constraints, or brand guidelines—and may not be discovered until after publication.

**Model and agent memory poisoning.** The FL Studio scripting skill documentation warns of agent memory poisoning, in which attacker-controlled rules are written into memory and affect later sessions. A poisoned memory can cause an agent to persistently treat a dangerous operation as routine, or to treat an attacker-controlled path as an approved output location. Memory poisoning is the agentic equivalent of a configuration backdoor.

### 3.5 Credential and Identity Theft

The music-production workstation holds valuable credentials: DAW licenses, plugin license keys, cloud collaboration accounts, sample-library subscriptions, distribution platform accounts, and, increasingly, API keys for AI music services. The Suno breach exposed 55.3 million unique accounts, including names, physical addresses, email addresses, phone numbers, purchases, and partial payment card numbers with expiry dates. The stolen data also included Suno’s source code, which revealed how the company allegedly scraped millions of songs and lyrics from Deezer, Genius, and YouTube to train its AI models. The breach happened in November 2025 but was only revealed in July 2026, and the company had not publicly disclosed the cyberattack or notified individuals at the time of reporting.

Credential theft at the AI-service layer is compounded by credential theft at the workstation layer. Infostealers now collect credentials from AI coding tools, and at least 15 malicious IDE plugins posing as AI coding assistants have been documented. The Acronis TRU Cyber Pulse 2026 report notes that malware is targeting API keys and credential files associated with AI development tools alongside GitHub tokens. For a producer who uses the same machine for music production and AI-assisted development, a single infostealer can capture the entire credential surface: DAW licenses, plugin vendor accounts, cloud project storage, distribution accounts, and AI service keys.

---

## 4. Structural Vulnerabilities of the DAW Workstation

The case studies above are not a random collection of incidents. They exploit a consistent set of structural properties of the DAW workstation.

### 4.1 In-Process Execution with Full User Privileges

Plugins execute inside the DAW host process with the full privileges of the logged-in user. There is no meaningful sandbox between a plugin and the user’s home directory, SSH keys, browser cookies, cloud credentials, or project files. The VST3 specification does not require sandboxing, and most DAWs do not provide it. A malicious plugin can read and write any file the user can read and write, make network connections, spawn processes, and persist itself. The plugin-scanning process may also execute code, which means that even opening the DAW can trigger execution of a malicious plugin before the user has deliberately loaded it.

This property is the root cause of the arbitrary-file-write-to-code-execution chain in Phantom-Audio. The MCP server runs as the user, and the DAW runs as the user, and the shell startup file is writable by the user. There is no privilege boundary to cross; the attacker only needs to redirect a write.

### 4.2 Broad Filesystem Permissions and Weak Path Confinement

MCP servers and AI skills typically run with the same broad filesystem permissions as the user. Path confinement is not enforced by the operating system unless the process is sandboxed or containerized, and most music-production tools are not. The Phantom-Audio advisory is explicit: the server failed to construct a restricted canonical base directory, did not invoke canonicalization functions, and did not verify that target paths resolved inside a dedicated sandbox directory. The fix in version 1.3.1 added strict sandbox confinement using canonicalized path verification and atomic writes to protect against time-of-check-to-time-of-use symlink swapping. This is the correct pattern, but it must be applied to every tool that accepts a path, not only to the one that was disclosed.

### 4.3 Unbounded Audio Ingestion

Audio decoders are expected to handle large files, and the line between a legitimate large session and a decompression bomb is not always obvious at the byte level. A FLAC file that is a few kilobytes compressed can legitimately represent several minutes of silence, but it can also be crafted to expand to an allocation that exceeds available memory. Without duration, frame-count, sample-rate, and channel-count limits enforced before PCM expansion, the decoder is a denial-of-service primitive. The Phantom-Audio, SGLang, libsndfile, dr_flac, and dr_wav vulnerabilities all fit this pattern.

### 4.4 Trust in Installers and Update Channels

The music-production community has normalized the download of executables from forums, file-sharing sites, YouTube descriptions, and unofficial repositories. The DinDoor campaign exploited this normalization directly, using fake GitHub and SourceForge repositories and compromised YouTube channels to distribute installers impersonating Ableton Live, Kontakt, AutoTune, and ZENOLOGY. The LoudMiner campaign exploited the same normalization in 2019, and the 2026 macOS loader campaign used cracked music software as its primary lure. Code-signing and notarization are effective mitigations, but they are inconsistently applied in the plugin ecosystem, and unsigned installers frequently trigger only a generic SmartScreen warning that users have learned to dismiss.

### 4.5 High-Value Project Data and Low-Backup Culture

Music project files represent months or years of creative work, and they are often stored on a single workstation with insufficient backup. The Zrythm ransomware attack encrypted entire music libraries and caused an estimated $2.3 million in lost projects and downtime. The value of the data makes the workstation a ransomware target, and the low-backup culture increases the impact of any destructive event, whether malicious or accidental. An AI agent that performs a destructive file operation without confirmation can cause damage comparable to ransomware, even without an attacker.

### 4.6 The Collapse of the Developer/Musician Boundary

The final structural vulnerability is cultural. The tools of software development and the tools of music production have merged. A producer may use a code editor to write a REAPER script, a Python environment to run a stem-separation model, a package manager to install an audio library, and an MCP server to connect a language model to a DAW. Each of these tools brings its own supply chain, and each supply chain has been targeted. GlassWorm targeted developer extensions; DinDoor targeted music-production installers; Phantom-Audio targeted the MCP layer between them. The producer who does not think of themselves as a developer is nevertheless operating a developer toolchain, and the security posture of that toolchain is now part of the security posture of the studio.

---

## 5. The Watchtower Pattern: A Human-in-the-Loop Detection Architecture

The threats described above cannot be solved by a single product, a signature feed, or a policy document. They require an architecture that assumes compromise is possible, that assumes the defender cannot anticipate every attack, and that assumes automated enforcement in a creative environment will eventually cause unacceptable collateral damage. The Watchtower Pattern is such an architecture.

### 5.1 Core Philosophy: Detection and Review, Not Enforcement

Watchtower is explicitly a detection-and-review system, not an enforcement system. The core harness observes, scores, explains, and queues findings. A human decides. The project’s README states the position directly: “That is not a weakness. That is the only architecture that survives contact with a real SOC and a real legal department.” The design constraints are enforced by construction: no network calls or telemetry, no screen capture or keystroke logging, no writing-style or “AI-ness” scoring, no automatic block, delete, or report, no contacting anyone, and advisory tiers only. The rationale for each constraint is explicit: a detection tool with a phone-home is an exfiltration tool with extra steps; surveillance primitives are not security primitives; writing-style scoring is an invalid signal with disparate impact; and an advisory tier that fires an action is no longer advisory.

This philosophy is not a concession to weakness. It is a response to the operational reality of creative work. A DAW session is a real-time, stateful, deeply personalized environment. An automated enforcement system that quarantines a plugin during a session may destroy hours of work. An automated system that deletes a “suspicious” file may delete a legitimate sample library. An automated system that blocks an MCP tool call may interrupt a render that cannot be reproduced. The cost of a false positive in a creative environment is not a minor inconvenience; it is lost work, missed deadlines, and damaged trust in the security tool itself. Watchtower’s answer is to separate detection from action: the harness can be aggressive in what it observes and scores, because the human reviewer retains the authority to decide what to do.

### 5.2 Threat Model and Response Tiers

Watchtower targets two converging attack surfaces: browser-resident online agents operating inside a real web session with cookies, form-fill authority, and tool-call authority; and desktop application harnesses—local processes that touch files, shells, credentials, and the network. The music-production workstation sits squarely in the second category, and increasingly in the first as DAW sessions are connected to cloud collaboration and AI services.

The response tiers are advisory only. A score of 0.85 or higher is critical, with guidance to review immediately and consider isolating the path by hand. A score of 0.65 or higher is high, with guidance to review today and corroborate before acting. A score of 0.45 or higher is medium, with guidance to review this week. Below 0.45 is low, with guidance to record only. The harness prints these tiers; it does not execute them.

The threat model maps adversary moves to detection signals and adapters. Prompt injection and instruction override map to input_injection_pattern in the InputAnomaly adapter. Encoded payload smuggling in URL parameters, environment variables, or argv maps to input_encoded_payload. Bidi and control-character spoofing map to input_control_characters. Trojanized binaries and dropped files map to file_added and file_modified in the FileIntegrity adapter. Permission escalation on disk maps to file_permission_change. Novel command-and-control sources map to auth_new_source in the AuthLog adapter. The model is extensible, and the music-production domain requires additional adapters and rules that the current repository does not yet include.

### 5.3 Why Human-in-the-Loop Is the Correct Architecture for Music Production

The human-in-the-loop architecture is particularly well suited to music production for three reasons.

First, the ground truth is contextual. A plugin that writes to ~/.zshrc is almost certainly malicious, but a plugin that writes to ~/Music/Exports/ may be entirely legitimate. A tool call that renders audio to /tmp/ may be suspicious in one workflow and expected in another. A human reviewer with knowledge of the session, the project, and the user’s intentions can distinguish these cases in a way that a static rule cannot. The harness’s job is to surface the finding with enough context—the tool name, the argument value, the rule that fired, and the explanation—for the reviewer to make an informed decision.

Second, the cost of false positives is asymmetric. A missed detection may result in a compromised workstation, but an automated false positive may result in a destroyed session. In a creative environment, the expected cost of automated enforcement is higher than the expected cost of human review, because the human reviewer can exercise judgment that the automation cannot.

Third, the legal and professional context favors documented human decisions. A studio that can demonstrate a review process, a rationale for each action, and a record of who decided what and when is in a stronger position than a studio that relies on an opaque automated system. The Watchtower review command forces the reviewer to enter a name and a rationale, and the report command produces an auditable record. This is not bureaucracy; it is the minimum standard for a security process that may be examined after an incident.

---

## 6. Extending Watchtower to AI-Coded Plugins and DAW Workstations

The current Watchtower harness is a general-purpose detection core. Extending it to the music-production domain requires a new scanner module, a set of domain-specific detection rules, and an integration with the existing scoring and review queue. The following specification is designed to be implementable in a stdlib-only Python module and to preserve the project’s design constraints.

### 6.1 New Scanner Module: ai_music_mcp_scanner.py

The scanner should ingest JSON-RPC 2.0 MCP tool-call logs from a file path or standard input. For each tools/call request, it should extract the tool name, the arguments dictionary, and the server identifier. It should also ingest filesystem state for plugin directories, startup scripts, and skill directories, and it should optionally ingest package-manager manifests and lockfiles.

The scanner must not make network calls, must not capture screen contents or keystrokes, and must not automatically modify or delete any file. Its output is a set of findings that are written to the existing harness.db schema with a new surface column value of "ai_music_mcp".

### 6.2 Detection Rule A: MCP Output Path Traversal

**Trigger.** Any tool argument key matching (output|export|save|write|render)_?path or audio_path contains an absolute path (starting with / or a Windows drive letter) and does not start with a configured allowlisted prefix such as PHANTOM_OUTPUT_DIR.

**Score.** 0.95, critical tier.

**Explanation.** “MCP tool ‘{tool_name}’ accepted unconfined absolute path ‘{arg_value}’. This enables arbitrary file write and local code execution, including overwriting shell startup files or DAW startup scripts (ref: GHSA-52vm-mxx8-f227, CVE-2026-65701).”

**Suggested review action.** Confirm the agent session origin. Check whether the target path is a shell startup file (~/.zshrc, ~/.bashrc), a REAPER __startup.lua, a DAW project file, or a plugin directory. Quarantine the MCP session if the target is outside the expected output directory.

The rule should also flag relative paths that contain .. segments after normalization, and paths that resolve through symbolic links outside the allowlisted prefix. The implementation should use os.path.realpath and compare the canonicalized result against the canonicalized allowlist prefix, not against the raw string.

### 6.3 Detection Rule B: Audio Decompression Amplification

**Trigger.** A tool call references an input audio file with a compressed format (.flac, .ogg, .mp3, .wav with compressed codecs) whose file size is below a threshold (for example, 5 MB) but whose decoded PCM duration estimate exceeds a threshold (for example, 10 minutes) or whose decoded memory estimate exceeds a threshold (for example, 500 MB).

**Score.** 0.80, high tier.

**Explanation.** “Potential audio decompression bomb: a small compressed input may expand to a multi-gigabyte PCM buffer, causing memory-exhaustion denial of service and increasing exposure to decoder memory-safety vulnerabilities (ref: GHSA-52vm-mxx8-f227, CVE-2026-109226, CVE-2026-37555).”

**Suggested review action.** Isolate the MCP server process. Check memory limits and decoder library versions. Review the input file’s provenance and metadata.

The duration estimate can be computed from the compressed file’s metadata without fully decoding it, using header parsing for FLAC, OGG, and WAV. If metadata is unavailable or inconsistent, the rule should escalate rather than suppress.

### 6.4 Detection Rule C: Caption and Prompt Poisoning Indicators

**Trigger.** A tool call to a retrieval-augmented generation endpoint where the prompt or caption argument contains mixed-script homoglyphs within a single word, unusual Unicode control or bidirectional characters, or sub-lexical phonetic patterns that deviate from the surrounding text.

**Score.** 0.60, medium tier.

**Explanation.** “Possible caption poisoning attempt: the prompt contains obfuscated phonemes or mixed-script homoglyphs designed to bypass text filters and steer generation (ref: ‘Mental Damage’ caption poisoning, ‘Bob’s Confetti’ adversarial phonetic prompting).”

**Suggested review action.** Compare the retrieved caption against the baseline caption distribution. Flag the caption source for integrity review. If the caption was retrieved from an external database, verify the database’s access controls and update integrity.

This rule is necessarily heuristic, and it should be tuned to avoid flagging legitimate multilingual text or intentional stylistic variation. The score is medium rather than high because the false-positive rate is likely to be higher than for path traversal or decompression bombs, and the consequence of a false negative is data integrity rather than code execution.

### 6.5 Detection Rule D: Unpinned Package Installation in Startup

**Trigger.** A startup script, skill manifest, or MCP server initialization file contains a pip install, npm install, cargo install, or similar package-manager invocation without a version pin (==, @version) or hash verification (--require-hashes, lockfile reference).

**Score.** 0.85, high tier.

**Explanation.** “Startup script auto-installs unpinned packages. This introduces a supply-chain execution path where a compromised index or dependency-confusion attack can execute arbitrary code at startup (ref: Suno V5 skill audit; GlassWorm developer-extension campaign).”

**Suggested review action.** Freeze dependencies. Require a hash-pinned lockfile. Review the package sources and the registry configuration. Consider running the skill in a container or virtual environment with a restricted package index.

### 6.6 Detection Rule E: Unauthenticated Control Endpoint

**Trigger.** A static scan of a skill or MCP server source finds a route such as /shutdown, /restart, or /config that performs a state-changing action without an authentication decorator or authorization check.

**Score.** 0.55, medium tier.

**Explanation.** “Unprotected control endpoint ‘{route}’ allows unauthenticated denial of service or state manipulation (ref: Suno V5 /shutdown endpoint; Acronis TRU Cyber Pulse 2026 agent-gateway exposure).”

**Suggested review action.** Add authentication middleware. Restrict the endpoint to localhost or a trusted network. Remove the endpoint if it is not essential for music generation.

### 6.7 Baseline Profile for DAW Environments

The scanner should accept a daw_profile.json file with the following keys: allowed_output_dirs (a list of absolute path prefixes), expected_tools (a list of tool names that are expected in the environment), max_audio_duration_sec (an integer), allowed_package_registries (a list of registry URLs), and plugin_directories (a list of paths). If a tool call falls outside the baseline—an unexpected tool name, an output path outside the allowed directories, a package registry outside the allowlist—the score should be escalated by 0.10 and the explanation should note the baseline deviation.

The baseline profile should be stored under ~/.watchtower/ alongside harness.db and baseline.json, and it should be version-controlled so that changes are auditable.

### 6.8 Integration with Existing Harness Scoring and Review Queue

Findings from the AI Music MCP scanner should be written into harness.db with the same schema as existing findings, plus the surface column. The report command should include an “AI Music / DAW MCP” section with columns for surface, tool, rule ID, score, explanation, and queued-for-review status. The review command should require the reviewer to enter a rationale and an MCP session identifier for traceability.

The scanner must not add automatic blocking. It should print findings and append them to the review queue. The reviewer decides whether to quarantine a session, isolate a path, update a plugin, or take no action.

### 6.9 Implementation Notes

The scanner can be implemented with the Python standard library. JSON-RPC parsing uses json. Path canonicalization uses os.path.realpath and os.path.commonpath. Audio metadata parsing can be implemented for FLAC, OGG, and WAV headers without external libraries; for formats that cannot be parsed with stdlib alone, the scanner should emit a low-confidence finding rather than skip the file. Static analysis of startup scripts can use regular expressions for package-manager invocations and route definitions, with the caveat that regular expressions are not a substitute for a full parser and may produce false negatives on obfuscated code.

The scanner should be tested against synthetic malicious and benign inputs, including a path-traversal tool call, a small FLAC file with a large duration header, a poisoned caption containing mixed-script homoglyphs, a startup script with an unpinned pip install, and a source file with an unauthenticated /shutdown route. The test suite should also include benign cases such as a tool call that writes to the configured output directory, a short FLAC file, a multilingual caption, a pinned dependency installation, and an authenticated control endpoint.

---

## 7. Governance, Legal, and Operational Considerations

### 7.1 The Advisory-Only Constraint and Liability

The decision to keep Watchtower advisory is not only an operational choice; it is a liability-management choice. An automated enforcement system that destroys a user’s project may expose the deployer to claims of negligence or breach of contract. An advisory system that documents findings, requires a human decision, and records the rationale provides a defensible record of reasonable care. In a professional studio, the security process must be compatible with the creative process, and a process that can interrupt a session without human authorization is not compatible.

### 7.2 Data Minimization and Privacy

Watchtower’s design constraints prohibit screen capture, keystroke logging, and writing-style scoring. These constraints are particularly important in a music-production environment, where the workstation contains unreleased creative work, personal communications, and potentially sensitive client information. A security tool that captures screen contents or keystrokes in a studio is a surveillance tool, and it creates a new data-protection obligation that may outweigh the security benefit. The harness should collect only the metadata necessary to evaluate the detection rules: tool names, argument values, file paths, file sizes, and package-manifest contents.

### 7.3 Retention and Audit

The purge --days 90 command allows the operator to enforce a retention policy. In a studio context, a 90-day retention window is reasonable for operational findings, but incident-related findings may need to be retained longer for legal or insurance purposes. The review rationale and the decision record should be retained according to the studio’s legal obligations, and the purge policy should be documented in the operating procedure.

### 7.4 Reviewer Competence and Escalation

The human-in-the-loop architecture depends on the competence and availability of the reviewer. A reviewer who does not understand MCP tool calls, audio decoding, or package-management supply chains will not be able to make informed decisions. Studios should designate at least one person with security literacy, provide training on the specific detection rules, and establish an escalation path for critical findings. The Acronis TRU Cyber Pulse 2026 report notes that a single operator can now achieve APT-like scale using AI agents, which means that a critical finding may require external incident-response support. The escalation path should identify the external support contact before an incident occurs.

### 7.5 Vendor and Platform Responsibility

The detection rules described in this paper are compensating controls. They do not absolve vendors of their responsibility to build secure tools. MCP server developers should enforce path confinement by default, not only when an environment variable is set. Audio-decoding libraries should enforce duration, frame-count, and channel limits before allocation. Package managers should default to locked installations. DAW vendors should provide plugin sandboxing options and should sign and verify plugin binaries. AI coding tools should not use model judgment as a security boundary. The Watchtower pattern is necessary because these responsibilities are not yet universally met, but it is not a substitute for meeting them.

---

## 8. Honest Gaps and Failure Modes

### 8.1 Detection Coverage Is Incomplete

No detection rule set can cover every attack. The rules proposed here cover the known vulnerabilities and campaigns documented in this paper, but new attack patterns will emerge. The caption-poisoning rule is heuristic and may miss sophisticated attacks. The path-traversal rule depends on the argument key naming convention and may miss tools that use unconventional parameter names. The decompression-bomb rule depends on metadata parsing and may be evaded by crafted headers. The unpinned-install rule depends on static analysis and may be evaded by obfuscated startup scripts. The unauthenticated-endpoint rule depends on route definition patterns and may miss dynamically registered routes.

### 8.2 False Positives and Reviewer Fatigue

The human-in-the-loop architecture trades automation for judgment, but it also creates reviewer workload. A high volume of medium-tier findings can cause reviewer fatigue, and a fatigued reviewer may approve a dangerous action without adequate scrutiny. The scoring thresholds should be tuned to the environment, and the reviewer should have the ability to mark findings as expected or benign with a documented rationale. The baseline profile is one mechanism for reducing false positives; periodic review of the baseline is another.

### 8.3 The Tool Cannot See Encrypted or Obfuscated Payloads

The scanner operates on plaintext tool calls and files. If an attacker encrypts a payload, encodes it in a format the scanner does not parse, or delivers it through a channel the scanner does not observe, the scanner will not detect it. The harness is one layer of defense, not the only layer. It should be combined with endpoint protection, network monitoring, and application-level sandboxing where available.

### 8.4 The Human May Make the Wrong Decision

The architecture assumes that the human reviewer is competent, available, and not under pressure to approve an action. In practice, reviewers are sometimes tired, distracted, or pressured to keep a session running. The review command should require a rationale, and the report should be auditable, but no process can guarantee that every human decision is correct. The goal is to make the correct decision the easy decision and to create a record that supports learning from mistakes.

### 8.5 The Watchtower Repository Is a Starting Point, Not a Product

The Watchtower Pattern repository is a well-designed detection core, but it is not a finished commercial product. It does not include the AI Music MCP scanner described in this paper, and the adapters directory is a placeholder for future extracted adapters. Studios that adopt the pattern will need to implement, test, and maintain the domain-specific rules. The value of the pattern is the architecture and the design constraints, not the completeness of the current rule set.

---

## 9. Conclusion

The trust boundary that the music-production industry forgot it had is the plugin folder, the MCP tool call, and the AI-generated startup script. These are not passive artifacts. They are executable code, unconfined write primitives, and supply-chain entry points. The empirical record—Zrythm, Phantom-Audio, Suno, DinDoor, GlassWorm, Sound Radix, and the caption-poisoning attacks on retrieval-augmented text-to-music systems—demonstrates that adversaries have already recognized the value of the music-production workstation and the relative weakness of its defenses. The response cannot be to reject AI assistance or to retreat from networked tools; the economic and creative pressures are too strong. The response must be to rebuild the trust boundaries deliberately, with detection that is aggressive enough to surface the threats and a review process that is cautious enough to avoid destroying the work the security system exists to protect.

The Watchtower Pattern provides a defensible architecture for this response. It observes, scores, explains, and queues findings; it does not automatically block, delete, or report; it does not phone home, capture screens, or score writing style; and it requires a human to make every consequential decision. The detection rules proposed in this paper—MCP output-path confinement, audio decompression amplification, caption and prompt poisoning indicators, unpinned package installation, and unauthenticated control endpoints—extend the pattern to the specific threats facing AI-coded plugins and DAW workstations. They are implementable with the standard library, testable against synthetic inputs, and compatible with the project’s design constraints.

The deeper lesson is that security in a creative environment is not the absence of risk; it is the presence of judgment. An automated enforcement system that quarantines a plugin during a session may be technically correct and professionally catastrophic. A human reviewer who understands the session, the project, and the stakes can make a decision that no rule can encode. The Watchtower Pattern’s most important contribution is not its detection logic but its insistence that the human remains in the loop. In a studio, as in a security operations center, the architecture that survives contact with reality is the one that knows what it cannot decide.

---

## References

1. Artists in DSP. “Vibe Coding VST Plugins: What Actually Happens After the Code Compiles.” September 2026.
2. Bright Coding. “Revolutionize Your Music Production: Why Automation-Ready DAWs Are Game-Changers in 2025.” November 2025.
3. ZenOne Music. “Everything in That Folder Runs.” August 2026.
4. GitLab Advisory Database. “Phantom-Audio: Arbitrary File Write and Decode-Bomb DoS via Unconfined MCP Tool Paths.” 2026.
5. Schendel, A. “GHSA-52vm-mxx8-f227: Arbitrary File Write and Decompression Denial of Service in phantom-audio.” CVEReports, July 2026.
6. Wen, Y., Zhang, S., et al. “Mental Damage: Caption Poisoning Attacks on Retrieval-Augmented Text-to-Music Generation.” IEEE Symposium on Security and Privacy Workshops, 2026.
7. TechCrunch. “AI Music Generator Suno Breach Affects 55M Users, per Have I Been Pwned.” July 2026.
8. Mallory. “Fake GitHub and SourceForge Software Delivered DinDoor Deno RAT.” May 2026.
9. VulDB. “CVE-2026-30304 in AI Code.” March 2026.
10. ThaiCERT. “GlassWorm Returns with Over 24 Malicious Extensions Targeting Developers via VS Code and Open VSX.” December 2025.
11. Acronis. “Acronis TRU Cyber Pulse 2026.” November 2026.
12. Heise Online. “IT Incident at Music Plug-in Maker Sound Radix: Nearly 300,000 Accounts Leaked.” March 2026.
13. VulDB. “CVE-2026-37555 in libsndfile.” April 2026.
14. Seals, L. J. “The Watchtower Pattern: Exhaustive Security Remediation for Browser Agents and Desktop Harnesses—with a Human-in-the-Loop Detection Core.” GitHub repository, 2026.
15. SGLang Security Advisory. “CVE-2026-109226: Decompression Amplification in load_audio.” 2026.
16. VCV Community. “False Alarm or Possible Malware (Poseidon Stealer) in Several Plugins?” 2026.
17. ClawHub. “FL Studio Scripting—Security Analysis.” 2026.
18. Mallory. “GlassWorm Supply Chain Attack via Malicious VS Code and Open VSX Extensions.” December 2025.
19. Cloud Security Alliance Labs. “GlassWorm Zig Dropper: Cross-IDE Developer Supply Chain Attack.” April 2026.
20. MCP Observatory. “Xdarkzx Reaper MCP Server Security.” 2026.

---

## Editorial and verification status

This file preserves the manuscript supplied by the authors. The incident descriptions, dates, statistics, vulnerability identifiers, and bibliographic entries have not been independently verified as part of this repository commit. Before external publication, each reference should be replaced or supplemented with a stable primary-source URL, advisory identifier, publication date, and access date. Claims that describe alleged incidents should be clearly distinguished from independently confirmed technical advisories and research findings.
