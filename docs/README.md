# PesaGuard Documentation

This directory is organized by system concern and is intended to describe the platform’s actual structure, operational boundaries, and product responsibilities.

## Architecture foundation

The system foundation is documented here:

- [architecture/SYSTEM_ARCHITECTURE.md](architecture/SYSTEM_ARCHITECTURE.md) — purpose, boundaries, actors, responsibilities, and overview
- [architecture/COMPONENT_ARCHITECTURE.md](architecture/COMPONENT_ARCHITECTURE.md) — component model and runtime responsibilities
- [architecture/SERVICE_BOUNDARIES.md](architecture/SERVICE_BOUNDARIES.md) — clear ownership and interface boundaries
- [architecture/DEPENDENCY_MAP.md](architecture/DEPENDENCY_MAP.md) — internal and external service dependencies
- [architecture/DATA_FLOW.md](architecture/DATA_FLOW.md) — how money and events move through the platform
- [architecture/EVENT_ARCHITECTURE.md](architecture/EVENT_ARCHITECTURE.md) — event taxonomy, routing, and consumers
- [architecture/TRUST_BOUNDARIES.md](architecture/TRUST_BOUNDARIES.md) — validation points and sensitive boundaries
- [architecture/SYSTEM_INVARIANTS.md](architecture/SYSTEM_INVARIANTS.md) — the rules the platform must never violate
- [architecture/ENGINEERING_PRINCIPLES.md](architecture/ENGINEERING_PRINCIPLES.md) — the design principles the team follows

## Data engineering foundation

- [database/CORE_DATA_ENGINEERING.md](database/CORE_DATA_ENGINEERING.md) — ingestion, canonical model, transformations, lineage, catalog, retention, and governance
- [database/DATA_DICTIONARY.md](database/DATA_DICTIONARY.md) — field-level definitions for the platform’s core entities

## Algorithm foundation

- [algorithms/TRANSACTION_INTELLIGENCE.md](algorithms/TRANSACTION_INTELLIGENCE.md) — implemented transaction-intelligence primitives, matching guardrails, validation and future algorithm roadmap

## Supporting documentation

- [api/](api/) — public API contracts
- [integrations/](integrations/) — payment and communication providers
- [domains/](domains/) — domain behavior and workflows
- [database/](database/) — schema, migrations, retention, backups, and restore procedures
- [security/](security/) — security controls and threat management
- [infrastructure/](infrastructure/) — local and hosted platform setup
- [operations/](operations/) — deployment and operational procedures
- [runbooks/](runbooks/) — incident-specific response guides
- [development/](development/) — contribution and engineering workflow
- [testing/](testing/) — test strategy and test data
- [observability/](observability/) — logs, metrics, traces, health checks, and SLOs
- [compliance/](compliance/) — governance and residency requirements
- [product/](product/) — product scope and workflows
- [decisions/](decisions/) — architecture decision records

## Decision records

- [decisions/ARCHITECTURE_DECISION_RECORDS.md](decisions/ARCHITECTURE_DECISION_RECORDS.md)
- [decisions/ADR-001-MODULAR-MONOLITH.md](decisions/ADR-001-MODULAR-MONOLITH.md)
- [decisions/ADR-002-POSTGRESQL.md](decisions/ADR-002-POSTGRESQL.md)
- [decisions/ADR-003-KAFKA.md](decisions/ADR-003-KAFKA.md)
- [decisions/ADR-004-REDIS.md](decisions/ADR-004-REDIS.md)
- [decisions/ADR-005-PROVIDER-ADAPTERS.md](decisions/ADR-005-PROVIDER-ADAPTERS.md)
- [decisions/ADR-006-MULTI-TENANCY.md](decisions/ADR-006-MULTI-TENANCY.md)
- [decisions/ADR-007-AWS-ARCHITECTURE.md](decisions/ADR-007-AWS-ARCHITECTURE.md)
