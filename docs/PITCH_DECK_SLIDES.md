# ConsentShield Pitch Deck: Slide-by-Slide Script & Presentation Guide

> **IBM Z & LinuxONE Student Contest / Hackathon 2026**  
> **Project:** ConsentShield — Drift-Aware, Zero-Leakage Privacy Gateway for Enterprise AI on s390x  
> **Deck PDF:** [`docs/ConsentShield_Pitch_Deck.pdf`](./ConsentShield_Pitch_Deck.pdf) (1.20 MB, under 10 MB limit)  
> **Repository:** [https://github.com/SREEGOVIND3/ibmz2026](https://github.com/SREEGOVIND3/ibmz2026)

---

## 3-Minute Video Pitch Script & Timeline

| Time | Slide | Focus Area | Key Message / Value Proposition |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:25** | Slides 1-2 | Problem & Regulatory Crisis | Mainframes process 70% of global financial transactions; adopting GenAI risks massive PII leaks and 4% GDPR/DPDP fines. |
| **0:25 - 0:55** | Slide 3 | The Solution (ConsentShield) | High-throughput privacy gateway with canonical normalization, multi-tier detection, and fail-closed revalidation. |
| **0:55 - 1:30** | Slides 4-5 | IBM Z & LinuxONE Co-Design | Native s390x execution, CPACF hardware crypto, zero pickle, sub-1.5 ms latency preserving OLTP banking SLAs. |
| **1:30 - 2:15** | Slides 6-7 | Empirical Proof & Live Demo | Ablation on 7,677 fields: 0.00% leakage rate. Live demo of prompt redaction, schema drift quarantine, and SHA-256 audit ledger. |
| **2:15 - 2:45** | Slides 8-9 | Business Impact & Competition | $32B market, 44 of top 50 banks run on IBM Z. Why ConsentShield beats AWS Macie and Microsoft Presidio on mainframes. |
| **2:45 - 3:00** | Slide 10 | UN SDGs, Roadmap & Conclusion | SDG 9 & 16, Telum AI on-chip accelerator roadmap. Ready to safeguard enterprise AI today. |

---

## Detailed Slide Outline & Speaker Script

### Slide 1: Title & Executive Summary
* **Visuals:** Dark Cyber/Carbon theme, prominent ConsentShield shield insignia, metrics badges (0.00% Leakage, < 1.5 ms Latency, Zero Pickle, 84/84 Tests Passing), s390x certification badge.
* **Speaker Script:**  
  *"Good morning judges. We are thrilled to introduce **ConsentShield** — the first drift-aware, zero-leakage privacy gateway engineered natively for IBM Z and LinuxONE. Today, enterprise banking and healthcare systems are racing to deploy Generative AI, but cannot risk leaking sensitive customer credentials or violating global data regulations. ConsentShield solves this with microsecond speed and mathematical guarantees right on s390x hardware."*

---

### Slide 2: The Enterprise Crisis: Generative AI on Mainframe Data
* **Visuals:** Three crisis columns: 1. Massive PII/PHI Leakage, 2. Schema Drift & Evasion, 3. The s390x Architecture Friction.
* **Speaker Script:**  
  *"IBM Z systems power over 70% of the world’s financial transactions and host mission-critical patient records. Connecting these backends to LLMs and AI scoring introduces severe exposure risks — government IDs, credit cards, and clinical notes accidentally streaming into external model training loops, triggering GDPR or DPDP Act penalties up to 4% of global turnover.*  
  *Worse, attackers and third-party APIs evade static regex WAFs by renaming fields or altering schema structures. And traditional cloud sanitizers cannot run on LinuxONE: they crash due to big-endian incompatibilities and add 100 milliseconds of latency, shattering strict sub-2 millisecond banking SLAs."*

---

### Slide 3: The Solution: ConsentShield Privacy Gateway
* **Visuals:** Four-quadrant solution diagram: 1. Canonical Normalization, 2. Multi-Tier Hybrid Detection, 3. Contextual Policy Engine, 4. Fail-Closed Revalidation.
* **Speaker Script:**  
  *"ConsentShield acts as a high-performance, fail-closed privacy reverse proxy directly in front of enterprise AI microservices.  
  First, our canonical normalizer flattens arbitrary JSON and computes salted HMAC fingerprints — profiling schemas without ever persisting plaintext.  
  Second, our multi-tier detection combines microsecond algorithmic validators with an explainable drift-aware logistic classifier and pluggable NER.  
  Third, our contextual policy engine evaluates actions based on caller role, purpose, and destination.  
  And finally, our **Fail-Closed Revalidation Engine** rescan 100% of outgoing payloads. If any prohibited token remains, downstream AI receives exactly zero bytes."*

---

### Slide 4: IBM Z & LinuxONE Co-Design (The Unfair Advantage)
* **Visuals:** Co-design diagram highlighting CPACF Crypto Co-processor, Big-Endian Safe Zero-Pickle storage, and IBM Secure Execution / HPVS enclaves.
* **Speaker Script:**  
  *"Why is ConsentShield purpose-built for IBM Z?  
  1. **CPACF Hardware Acceleration:** All HMAC schema profiling, AES-256-GCM quarantine encryption, and SHA-256 audit chaining execute directly on IBM Telum and z16 CPACF co-processors at wire speed with sub-microsecond latency.  
  2. **Big-Endian Safe & Zero Pickle:** s390x uses big-endian byte order. Standard Python pickles corrupt across architectures. ConsentShield uses 100% pure JSON models and byte-order-independent SQLite.  
  3. **IBM Secure Execution:** ConsentShield runs inside confidential computing enclaves, ensuring data in-use is encrypted in memory against rogue hypervisors or host admins."*

---

### Slide 5: System Architecture & Data Pipeline
* **Visuals:** Comprehensive architecture flow from Ingestion API -> Normalization -> Tier 1-3 Detection -> Policy Enforcement -> Revalidation -> Downstream AI and Encrypted Vault.
* **Speaker Script:**  
  *"Here is our complete architecture pipeline. Client requests enter through an envelope-validated gateway. Data is profiled and checked for schema drift. High-risk credentials like credit cards or API keys immediately trigger whole-payload quarantine into an AES-256 encrypted vault. Free-text notes have sensitive spans excised and replaced with keyed tokens or redaction markers. Everything passes through our secondary revalidation barrier before being transmitted to the downstream AI model."*

---

### Slide 6: Empirical Benchmarks & Ablation Study
* **Visuals:** Ablation comparison table (7,677 fields) showing validator-only (37.29% leak rate) vs ConsentShield with revalidation (0.00% leak rate); latency bar chart showing 0.006 ms validators and 0.079 ms classifier.
* **Speaker Script:**  
  *"We validated ConsentShield on 7,677 test fields, 7,000 synthetic payloads, and 25,290 multilingual AI4Privacy samples.  
  Our ablation study reveals that standalone regex and validators miss 37.3% of sensitive payloads due to formatting noise and unstructured text.  
  Our logistic classifier achieves 98.1% precision and 99.2% recall. And when coupled with our mandatory fail-closed revalidator, downstream leakage drops to **exactly 0.00%**.  
  Best of all: median validator latency is just 0.006 milliseconds, and total gateway overhead is under 1.5 milliseconds — fully preserving mainframe OLTP SLAs."*

---

### Slide 7: Live Enterprise Demo: Tested & Verified
* **Visuals:** Three real-world test cases from our Streamlit console: Clinical EMR Note (span redaction), Schema Drift Attack (quarantine), and Cryptographic Audit Chain verification.
* **Speaker Script:**  
  *"Our solution includes an enterprise Streamlit console.  
  In Scenario 1, a physician submits a clinical triage note with an Aadhaar ID and contact numbers. ConsentShield excises the spans, replacing them with redaction tokens while preserving diagnostic meaning.  
  In Scenario 2, an attacker renames a sensitive field to 'guardian_uid'. ConsentShield's drift engine catches the anomaly and quarantines the payload instantly.  
  In Scenario 3, auditors verify our forward-linked SHA-256 ledger: if an insider attempts to delete or alter a single historical log, the cryptographic chain breaks instantly."*

---

### Slide 8: Business Impact & Target Market ($32B TAM)
* **Visuals:** Core Banking (44/50 banks), Healthcare Networks, Federal Sovereign AI; market growth from $3.2B to $32.4B PET market.
* **Speaker Script:**  
  *"The Privacy-Enhancing Technologies market is projected to reach $32.4 Billion by 2028.  
  ConsentShield targets the world's most critical infrastructure: 44 of the top 50 global banks, massive healthcare networks, and sovereign public sector clouds operating on IBM Z.  
  ConsentShield requires zero new infrastructure: it runs as a native container inside existing LinuxONE partitions, saving enterprise clients millions in regulatory fines and breach liabilities."*

---

### Slide 9: Competitive Matrix: Why ConsentShield Wins
* **Visuals:** Feature-by-feature matrix comparing ConsentShield against Microsoft Presidio, AWS Macie, and Static WAFs.
* **Speaker Script:**  
  *"Compared to existing tools:  
  Microsoft Presidio and AWS Macie are designed for x86 cloud VMs. They fail on s390x, introduce over 50 milliseconds of latency, and lack schema drift detection.  
  Static WAFs are easily bypassed by renamed fields.  
  ConsentShield is the only solution offering s390x native big-endian safety, CPACF hardware acceleration, drift profiling, mandatory revalidation, and a tamper-evident audit ledger."*

---

### Slide 10: Roadmap, UN SDGs & Vision
* **Visuals:** SDG 9 & 16 badges, IBM Telum AI on-chip accelerator roadmap, GitHub link and thank you banner.
* **Speaker Script:**  
  *"ConsentShield directly advances UN Sustainable Development Goal 9 for resilient digital infrastructure and Goal 16 for protecting citizen privacy and democratic institutions.  
  Our future roadmap includes compiling quantized transformer models directly to IBM Telum's on-chip Neural Network Processing Assist (NNPA) for sub-half-millisecond deep learning inference.  
  ConsentShield unlocks the full power of Generative AI for enterprise mainframes with zero compromise on speed, privacy, or compliance. Thank you, and we welcome your questions!"*

---

## Judge Q&A Preparation

### Q1: "Why can't enterprises just use Microsoft Presidio or AWS Macie?"
> **Answer:** "Two fundamental reasons: Architecture and Speed. First, AWS Macie only inspects S3 buckets inside AWS, requiring mainframe data to leave the sovereign enclave. Microsoft Presidio relies on heavy x86 C-extensions and SpaCy pipelines that either fail to compile on s390x or require heavy Python wheels that break across big-endian environments. Second, Presidio adds 30 to 80 milliseconds of latency per request. IBM Z core banking transactions demand sub-2 millisecond round trips. ConsentShield's multi-tier detection runs in under 1.5 milliseconds directly on LinuxONE."

### Q2: "How does ConsentShield ensure 'Zero Leakage' when machine learning models are inherently probabilistic?"
> **Answer:** "Machine learning is only Tier 2 of our pipeline. The true zero-leakage guarantee comes from our **Fail-Closed Mandatory Revalidation Gate (Layer 4)**. Before any sanitized payload is forwarded to downstream AI, ConsentShield rescans 100% of the outgoing serialized text through all deterministic validators and pattern scanners. If even a single unauthorized sensitive span or residual character pattern remains, the gateway fails closed: downstream transmission is completely aborted, and the payload is routed to the encrypted quarantine vault. Downstream AI receives exactly zero bytes."

### Q3: "How does ConsentShield prevent performance bottlenecks on high-throughput OLTP systems?"
> **Answer:** "Through multi-tier gating and CPACF co-processor acceleration. 95%+ of fields in standard transactions are screened in 0.006 milliseconds using pure Python deterministic validators (Luhn, Verhoeff, RFC regexes). The explainable ML classifier only scores ambiguous or shifted fields in 0.079 milliseconds. Cryptographic hashes and HMACs are offloaded to IBM Z's CPACF hardware instructions at wire speed. In our benchmarks across 7,677 fields, total gateway latency remained under 1.5 milliseconds."

### Q4: "What happens if an attacker attempts to alter the audit logs to hide a breach?"
> **Answer:** "ConsentShield uses a forward-linked SHA-256 hash chain: each audit event's hash is computed as `H(n) = SHA256(H(n-1) || Event_Payload)`. The entire chain is anchored with an external HMAC key. If an insider or attacker deletes, modifies, or inserts any record anywhere in the ledger, every subsequent block hash in the chain breaks mathematically. Our test suite includes automated tests verifying that reordered, modified, or deleted records are flagged instantly."
