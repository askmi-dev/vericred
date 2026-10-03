# VeriCred: Product Idea Review & Research

## 1. What is VeriCred?

**VeriCred** is a lightweight, open-source **OID4VCI issuer gateway**. Its primary goal is to allow organizations (like universities, employers, and guilds) to issue W3C Verifiable Credentials directly into European Digital Identity (EUDI) wallets, without requiring deep cryptographic or blockchain expertise.

The explicit value proposition is: **Go from existing database to issuing eIDAS 2.0-compliant credentials in under 30 minutes.**

Importantly, VeriCred is **strictly an issuer**. It is not a presentation layer or a wallet. It pairs with verification/presentation systems (referred to in the docs as "miTch").

## 2. Core Architectural Decisions

VeriCred abandons complex web3 paradigms in favor of standardized, web-native cryptography:

*   **No Blockchain:** Trust is derived purely from the issuer's signature (PKI), not a distributed ledger. This removes unnecessary complexity and aligns with eIDAS 2.0 institutional models.
*   **Protocol:** **OID4VCI (draft 13+)**. This is the native standard for EUDI wallets, ensuring high interoperability.
*   **Credential Format:** **SD-JWT-VC** (Selective Disclosure JWT Verifiable Credentials). This allows users to selectively disclose parts of their credential (e.g., proving they are over 18 without revealing their exact birthdate or name) and is highly compatible with presentation systems like miTch.
*   **DID Method:** **`did:web`**. Organizations host their Decentralized Identifier on their own domain (`/.well-known/did.json`), making it easy to deploy and retaining full control without ledger dependencies.
*   **Revocation:** **W3C StatusList2021**. A simple, signed JSON bitstring that doesn't require complex infrastructure, allowing verifiers to easily check if a credential is still valid.
*   **Deployment:** Designed to be self-hostable (Docker, Railway) or offered as a SaaS, prioritizing ease of deployment.
*   **Tech Stack:** Node.js, TypeScript, Express, leveraging established crypto libraries (`jose`, `@noble/curves`), with a frontend Admin UI built in Astro.

## 3. Key Components & Features

*   **Core Engine:** Handles the heavy lifting of SD-JWT-VC generation, key management (P-256 ECDSA), and `did:web` publishing.
*   **Dynamic Data Connectors:** A crucial feature that allows VeriCred to sit on top of existing infrastructure. It supports (or plans to support) connecting to PostgreSQL, MySQL, REST APIs, CSV uploads, or manual entry.
*   **Schema Mapping:** An Admin UI feature that lets non-technical users map their existing database columns (e.g., `student_id`, `graduation_date`) to standard credential claims using a drag-and-drop interface.
*   **Admin UI & OID4VCI Offer Flow:** A secure `/console` dashboard for onboarding, managing keys, revoking credentials, and generating OID4VCI offer QR codes/deep links for holders.
*   **Developer Playground:** Includes tools like a "Credential Packstation" and "Presentation Sandbox" to simulate issuance, selective disclosure, and verification flows directly in the browser.

## 4. Security & Privacy Model

Security and privacy are treated as first-class citizens:

*   **Strict Route Guarding:** Admin endpoints and static files are strictly protected by session cookies (`requireAdmin` middleware).
*   **Session-Bound CSRF:** Uses strict session-bound CSRF tokens for all mutating admin API calls to prevent cross-site request forgery.
*   **Default PII Masking:** Admin JSON APIs mask Personally Identifiable Information (emails, names) by default unless explicitly overridden (`PII_ADMIN_MODE`), preventing accidental data leaks.
*   **Pairwise Pseudonyms:** Uses HMAC-SHA256 scoped DIDs for holders to prevent tracking across different verifiers.
*   **Key Rotation:** Built-in atomic key rotation for issuer keys, maintaining a history in `did:web` for backward compatibility.

## 5. Current Progress & Roadmap (Based on `task.md`)

The project is currently executing "Phase 2" to "Phase 5" sprints, moving from a prototype to a production-hardened system:

*   **Phase 1 (MVP/Security):** Completed. Focused on securing the admin console, establishing the CSRF handshake, PII masking, and expanding the Offer API contract.
*   **Phase 2 (EUDI Interop & Connectors):** Completed/In Progress. Implementing CSV/Manual connectors and an EUDI-Wallet interoperability test suite.
*   **Phase 3 (Revocation):** Completed/In Progress. Implementing StatusList2021 cryptography and revocation workflows in the Admin UI.
*   **Phase 4 (Admin UX & Hardening):** Completed/In Progress. Dynamic schema introspection, setup wizards, key rotation UI, and Docker/SaaS portability.
*   **Phase 5 (Aesthetics & Sandbox):** Completed. "Warm-light" UI redesign and the interactive developer playground.

**Future Challenges (eIDAS 2.0 Path):**
The documentation explicitly identifies gaps for full production/eIDAS 2.0 compliance, including the eventual need for Post-Quantum Cryptography (PQK), Hardware-Level Assurance (HSMs) for LoA High, StatusList sharding for scale, and dynamic EUTL (European Union Trusted Lists) parsing.

## 6. Summary

VeriCred is a highly pragmatic, well-architected solution aimed at bridging the gap between legacy institutional databases and modern, privacy-preserving digital identity wallets. By eschewing blockchain for standard web PKI and focusing heavily on developer experience and zero-config onboarding, it positions itself as an essential utility for organizations adopting EUDI wallet standards.
