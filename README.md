# Kimia Vulnerability Scanner

Automated vulnerability management platform relying on Greenbone/OpenVAS.

## Setup Instructions

1. Ensure Docker and docker-compose are installed.
2. Build and start the services:
   ```bash
   docker-compose up --build
   ```
3. The API will be available at `http://localhost:8000`. 
4. The API documentation is at `http://localhost:8000/docs`.

## Architecture
The backend follows a Hexagonal Architecture, with code organized around business domains.

- `src/main.py`: Entrypoint
- `src/{module}/domain/`: Business logic and models
- `src/{module}/ports/`: Interfaces for adapters to implement
- `src/{module}/adapters/`: Implementations of ports (e.g., HTTP API endpoints, Database Repositories)
