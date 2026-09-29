# Kerubi Vulnerability Scanner (KVS) - Backend

Automated vulnerability management platform relying on Greenbone/OpenVAS, Nuclei, and Nmap, with a unified intelligence aggregation layer.

## Setup Instructions

1. Ensure Docker and docker-compose are installed.
2. Build and start the services:
   ``bash
   docker-compose up --build
   ``
3. The API will be available at http://localhost:8000. 
4. The API documentation is at http://localhost:8000/docs.

## Architecture
The backend follows a Hexagonal Architecture, with code organized around business domains.

- src/main.py: Entrypoint
- src/{module}/domain/: Business logic and models
- src/{module}/ports/: Interfaces for adapters to implement
- src/{module}/adapters/: Implementations of ports (e.g., HTTP API endpoints, Database Repositories)

## Core Capabilities
- **Multi-Engine Scanning**: Orchestrates OpenVAS, Nuclei, and Nmap for comprehensive asset discovery and vulnerability assessment.
- **Reporting Engine**: Generates professional PDF and HTML reports for executive overviews and detailed vulnerability insights.
- **AI-Powered Analysis**: Provides AI-generated remediation steps, business impact analysis, and contextual severity assessments.
- **Policy Management**: Full CRUD capabilities for dynamic policy tracking.
- **Deduplication**: Intelligent aggregation and deduplication of findings across multiple scanners based on CVE and signatures.

## Latest Updates
- Added dynamic policy deletion and modification logic.
- Expanded AI capabilities for Scan PDF report generation.
- Corrected UTF-8 string rendering bugs in reporting outputs.
