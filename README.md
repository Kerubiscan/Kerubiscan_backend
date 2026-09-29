# Kerubi Vulnerability Scanner (KVS) - Backend

![KVS Architecture Logo](https://img.shields.io/badge/Security-Scanner-blue?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.10%2B-green?style=for-the-badge) ![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688?style=for-the-badge)

The **Kerubi Vulnerability Scanner (KVS)** backend is an automated, high-performance vulnerability management platform. It acts as the core orchestration engine, aggregating intelligence from industry-standard scanners like **OpenVAS (Greenbone)**, **Nuclei**, and **Nmap**.

Built with a robust **Hexagonal (Ports and Adapters) Architecture**, the backend ensures clean separation of concerns, scalability, and maintainability.

## 🌟 Core Features

- **Multi-Engine Orchestration**: Seamlessly coordinates OpenVAS, Nuclei, and Nmap for comprehensive asset discovery and deep vulnerability assessments.
- **Intelligent Deduplication**: Automatically aggregates and deduplicates cross-engine findings based on CVEs, IP signatures, and vulnerability vectors, reducing alert fatigue.
- **AI-Powered Contextual Analysis**: Leverages AI to provide actionable remediation steps, contextual business impact analysis, and tailored severity assessments.
- **Advanced Reporting**: Dynamically generates highly polished, professional **PDF and HTML** executive and technical reports using `ReportLab` and `Jinja2`.
- **Policy & Secret Management**: Provides full CRUD capabilities to define dynamic security policies and manage vault secrets securely.
- **Task & Schedule Management**: Asynchronous task tracking for immediate, scheduled, and recurrent network scans.

## 📁 Architecture Overview

The backend is structured around domain-driven business logic:

```text
src/
├── main.py                     # FastAPI Application Entrypoint
├── ai/                         # AI-powered services for severity/impact analysis
├── assets/                     # Asset/IP management module
├── audit/                      # Audit logs and tracking
├── auth/                       # Authentication and authorization logic
├── companies/                  # Multi-tenant company management
├── core/                       # Core configurations, DB sessions, and shared exceptions
├── dashboard/                  # Dashboard statistics and KPIs
├── notifications/              # Alerting and notification module
├── policies/                   # Scan policies configuration (CRUD)
├── reporting/                  # Report generators (PDF, HTML via Jinja2/ReportLab)
├── scans/                      # Scan orchestration (OpenVAS, Nuclei, Nmap)
├── scheduling/                 # Recurrent scan scheduling and cron tasks
├── secrets/                    # Vault integration and secret management
└── vulnerabilities/            # Vulnerability intelligence and deduplication

Within each module (e.g., `scans/`), the Hexagonal architecture is strictly followed:
├── {module}/domain/            # Core Business logic, `entities.py` (SQLAlchemy), `models.py` (Pydantic)
├── {module}/ports/             # Abstract Interfaces for Repositories and Services
├── {module}/adapters/          # Implementations
│   ├── inbound/api/            # REST API endpoints (FastAPI routers, `endpoints.py`)
│   └── outbound/               # Database repositories (`repository.py`), external API clients
└── {module}/application/       # Use-cases and Orchestration Services
```

## 🚀 Setup & Installation

### Prerequisites
- Docker & Docker Compose
- PostgreSQL (Provided via Docker)
- OpenVAS / Greenbone Services (Provided via Docker)

### Running Locally

1. Clone the deployment repository (which includes this backend submodule).
2. Start the services using Docker Compose:
   ```bash
   docker compose up -d backend
   ```
3. The API will be accessible at: `http://localhost:9445`
4. Interactive API Documentation (Swagger UI): `http://localhost:9445/docs`

## 🛠️ Latest Updates
- **Scan PDF Reporting**: Introduced comprehensive PDF report generation for entire scan batches, detailing per-asset vulnerabilities and global statistics.
- **Policy Engine Upgrades**: Added full Edit (PUT) and Delete (DELETE) workflows for granular policy modifications.
- **Encoding Fixes**: Resolved UTF-8 character encoding issues (`Opérationnel`) across backend output streams.
