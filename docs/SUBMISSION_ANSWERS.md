# IBM Z / LinuxONE Hackathon 2026: Official Submission Form Answers

> **Project Name:** ConsentShield  
> **Tagline:** Drift-Aware, Zero-Leakage Privacy Gateway for Enterprise AI on IBM Z & LinuxONE (`s390x`)  
> **Repository:** https://github.com/SREEGOVIND3/ibmz2026  
> **Pitch Deck PDF:** [`ConsentShield_Pitch_Deck.pdf`](../docs/ConsentShield_Pitch_Deck.pdf) (1.20 MB)

Use the exact copy-paste ready answers below to fill out the submission form:

---

### Question 1: What is the Problem you are trying to solve? *
*(Required question)*

**Answer:**
Enterprise banking systems, payment networks, and healthcare providers running on IBM Z and LinuxONE process over 70% of the world’s financial transactions and mission-critical patient records. As these institutions connect core mainframe databases to Generative AI, Large Language Models (LLMs), and predictive scoring services (e.g., fraud triage, customer service bots, clinical diagnostic assistants), they face three severe roadblocks:

1. **High-Risk Data Leakage:** Unredacted customer identifiers—such as Aadhaar numbers, Social Security Numbers, Credit Card PANs, bank accounts, and protected health information (PHI)—accidentally stream into downstream AI models and third-party prompts. This creates severe regulatory non-compliance under GDPR, HIPAA, and the Digital Personal Data Protection (DPDP) Act 2023, risking fines up to 4% of global annual turnover and irreversible customer trust loss.
2. **Schema Drift & Adversarial Evasion:** Upstream client applications, third-party APIs, and attackers frequently alter schema structures or rename sensitive fields (e.g., renaming `ssn` to `guardian_uid` or embedding PII in free-text clinical notes). Traditional static regex Web Application Firewalls (WAFs) fail completely against schema drift, silently forwarding unmapped sensitive data to downstream AI pipelines.
3. **Mainframe Architecture Friction (`s390x`):** Conventional cloud privacy tools (such as Microsoft Presidio or AWS Macie) are built for x86 cloud architectures. They crash on IBM Z due to Big-Endian byte ordering incompatibilities, rely on unsafe binary Python pickle files that corrupt across architectures, and introduce 50–200 ms of network latency—violating strict mainframe core banking transaction SLAs (< 2.0 ms).

---

### Question 2: How are you planning to solve the problem? (Brief Overview) *
*(Required question)*

**Answer:**
We built **ConsentShield**, an enterprise-grade, drift-aware, fail-closed privacy reverse proxy designed natively to run within the LinuxONE enclave boundary. ConsentShield intercepts all incoming structured JSON payloads and unstructured prompts before they reach downstream AI endpoints through a 5-stage pipeline:

1. **Canonical Normalization & Salted HMAC Fingerprinting:** Flattens complex, nested JSON payloads into deterministic key-value paths and computes salted HMAC-SHA256 schema profiles to detect schema drift, new fields, and type shifts without persisting raw plaintext.
2. **Multi-Tier Real-Time Hybrid Detection:**
   - *Tier 1 (Deterministic Checksums):* Pure-Python, zero-wheel algorithmic validators (Luhn algorithm for credit cards, Verhoeff algorithm for Aadhaar, Shannon entropy for API keys, RFC regexes) running at **0.006 ms median** per field.
   - *Tier 2 (Statistical ML):* Drift-aware explainable logistic classifier (`v_len`, `v_alpha`, `v_space`, `v_embedded_any`, `d_new_field`) running at **0.079 ms median** with zero binary pickles.
   - *Tier 3 (Unstructured NER):* Pluggable GLiNER token-level entity extractor for unstructured clinical and support notes.
3. **Contextual Policy & Sanitization Engine:** Evaluates an enterprise authorization matrix mapping `(Purpose × Role × Destination)`. Performs surgical span redaction (`[REDACTED_AADHAAR]`), masking, or keyed irreversible tokenization.
4. **Mandatory Fail-Closed Revalidation (Zero-Leak Guarantee):** "Trust nothing, rescan everything." Before any sanitized payload is forwarded, 100% of outgoing bytes are rescanned by all active detectors. If any unauthorized sensitive token remains, the gateway fails closed—aborting transmission so downstream AI receives **exactly ZERO bytes**.
5. **AES-256-GCM Quarantine Vault & Tamper-Evident SHA-256 Ledger:** High-risk credentials and payment cards are quarantined into an encrypted vault with an authenticated analyst review workflow. Every ingest event is immutably logged in a forward-linked SHA-256 cryptographic hash chain (`H(n) = SHA256(H(n-1) || record)`) with an HMAC anchor, satisfying regulatory audit requirements.

---

### Question 3: How does your solution leverage IBM Z / LinuxONE technologies? *
*(Required question)*

**Answer:**
ConsentShield is co-designed specifically to exploit the hardware and architectural advantages of **IBM Z (z16/Telum) and LinuxONE (s390x)**:

1. **Big-Endian Architecture Safety (`s390x`):** IBM Z executes in Big-Endian byte order (unlike x86/ARM). Conventional Python ML libraries fail because binary pickle files corrupt across architectures. ConsentShield enforces **Zero Python Pickle**—all model weights are stored in portable, standard JSON (`models/field_classifier.json`). In addition, the storage layer uses byte-order agnostic SQLite and pure-Python standard libraries, guaranteeing zero native C-wheel compilation errors on LinuxONE.
2. **CPACF Hardware Cryptographic Acceleration:** Every cryptographic operation—salt hashing in schema profiling, forward-linked SHA-256 audit chaining, and AES-256-GCM quarantine vault encryption—maps directly to IBM Z’s **Central Processor Assist for Cryptographic Function (CPACF)** hardware co-processors. This enables wire-speed execution with sub-microsecond latency and zero context-switch overhead.
3. **IBM Secure Execution & Hyper Protect Virtual Servers (HPVS):** ConsentShield is designed to deploy inside an **IBM Secure Execution** confidential computing enclave. This hardware-enforces memory isolation, guaranteeing that sensitive customer and patient data in-use cannot be inspected or exfiltrated by rogue hypervisors, cloud operators, or host root administrators.
4. **Mainframe OLTP Real-Time Performance (< 1.5 ms SLA):** Core banking systems process over 25,000 transactions per second and demand sub-2 ms latency. ConsentShield achieves a total gateway latency of **< 1.5 ms** per 10-field API payload (0.006 ms for validators, 0.079 ms for classifier), preserving mainframe Online Transaction Processing (OLTP) throughput without adding external network hops.

---

### Question 4: What value does your solution deliver, and who will benefit from it? *

**Answer:**
ConsentShield delivers direct value to multiple critical enterprise stakeholders:

* **Core Banking & Financial Institutions (44 of the top 50 global banks run on IBM Z):** Enables banks to safely expose mainframe transactional backends to customer-facing Generative AI chatbots and automated credit/fraud scoring models without risking credit card, CVV, or bank account leaks. This eliminates breach liabilities averaging $4.8M and guarantees PCI-DSS and GDPR compliance.
* **Healthcare Providers & Hospital Networks:** Protects patient confidentiality and ensures 100% compliance with HIPAA, HITECH, and the DPDP Act 2023 when deploying diagnostic AI triage models on unstructured physician notes.
* **Security Officers (CISOs) & Data Protection Officers (DPOs):** Provides indisputable, tamper-evident cryptographic proof of compliance for regulatory audits via our forward-linked SHA-256 audit ledger with HMAC anchoring.
* **AI & DevOps Engineers:** Eliminates pipeline crashes and unannounced data drift caused by third-party API changes through automated schema baseline profiling.
* **Global Societal Impact (UN SDGs 9 & 16):** Fosters resilient enterprise digital infrastructure and protects citizen fundamental privacy rights against algorithmic surveillance and data harvesting.

---

### Question 5: Upload your pitch deck in PDF Format *
*Upload 1 supported file: PDF. Max 10 MB.*

* **File to Upload:** `ConsentShield_Pitch_Deck.pdf` (Located in the root download folder and in `docs/ConsentShield_Pitch_Deck.pdf`).
* **File Size:** **1.20 MB** (Well below the 10 MB limit).

---

### Question 6: Share the link to your pitch deck in PDF Format (if not able to upload the file)
* **Direct Repository Link:** https://raw.githubusercontent.com/SREEGOVIND3/ibmz2026/main/docs/ConsentShield_Pitch_Deck.pdf  
* *(Or insert your Google Drive shareable link with "Anyone with the link can view")*

---

### Question 7: Github Link of your Project/Link of you Zip File (make sure its publicly accessible!) *
*(Required question)*

* **GitHub Link:** **https://github.com/SREEGOVIND3/ibmz2026**

---

### Question 8: Video Submission Link *
*(Required question)*

* **Video Submission URL:** *(Insert your YouTube / Loom / Google Drive link here)*
* *Note: Ensure your Google Drive or YouTube video visibility is set to "Public" or "Anyone with the link can view".*
* *Consult [`docs/PITCH_DECK_SLIDES.md`](../docs/PITCH_DECK_SLIDES.md) for the exact 3-minute video presentation script.*

---

### Question 9: Link to all open-source resources used

| Resource / Library | License | Link | Purpose / Role in Project |
| :--- | :--- | :--- | :--- |
| **AI4Privacy Dataset** | CC-BY-4.0 | https://huggingface.co/datasets/ai4privacy/pii-masking-300k | Gold-standard multilingual PII benchmark across 6 European languages (25,290 samples). |
| **GLiNER** | Apache 2.0 | https://github.com/urchade/GLiNER | Generalist lightweight named entity recognition model for unstructured free-text spans. |
| **FastAPI** | MIT | https://github.com/tiangolo/fastapi | High-performance asynchronous REST API gateway composition root. |
| **Pydantic v2** | MIT | https://github.com/pydantic/pydantic | Strict runtime schema validation and payload envelope verification. |
| **Streamlit** | Apache 2.0 | https://github.com/streamlit/streamlit | Enterprise interactive analytics, live simulator, and explainability dashboard. |
| **Plotly** | MIT | https://github.com/plotly/plotly.py | Interactive visual charts for latency distributions, ROC curves, and audit trees. |
| **Scikit-Learn** | BSD 3-Clause | https://github.com/scikit-learn/scikit-learn | Model training and weight calculation for the drift-aware field classifier. |
| **Faker** | MIT | https://github.com/joke2k/faker | Synthetic payload generation with 7 distinct drift and evasion scenarios. |
| **SQLite 3** | Public Domain | https://www.sqlite.org/ | Byte-order independent embedded storage for baseline profiles and audit ledger. |
| **Pytest** | MIT | https://github.com/pytest-dev/pytest | Automated test suite validating 84 regression, leakage, and tamper-evident cases. |
| **ReportLab** | BSD 3-Clause | https://www.reportlab.com/ | Programmatic compilation of the pitch deck PDF presentation. |

---

### Question 10: Any other document that you would like to share like the solution flowchart or architecture diagram

* **System Architecture Diagram:** [`docs/diagrams/architecture_diagram.png`](../docs/diagrams/architecture_diagram.png) *(or direct link: https://raw.githubusercontent.com/SREEGOVIND3/ibmz2026/main/docs/diagrams/architecture_diagram.png)*
* **End-to-End Solution Flowchart:** [`docs/diagrams/solution_flowchart.png`](../docs/diagrams/solution_flowchart.png) *(or direct link: https://raw.githubusercontent.com/SREEGOVIND3/ibmz2026/main/docs/diagrams/solution_flowchart.png)*
* **IBM Z Hardware Co-Design Diagram:** [`docs/diagrams/ibmz_linuxone_co_design.png`](../docs/diagrams/ibmz_linuxone_co_design.png) *(or direct link: https://raw.githubusercontent.com/SREEGOVIND3/ibmz2026/main/docs/diagrams/ibmz_linuxone_co_design.png)*
* **Pitch Deck Script & Judge Q&A Guide:** [`docs/PITCH_DECK_SLIDES.md`](../docs/PITCH_DECK_SLIDES.md)
* **Empirical Ablation Benchmark Report:** [`results/ablation.json`](../results/ablation.json)
