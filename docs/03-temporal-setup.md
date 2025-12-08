# Temporal Setup

This guide covers setting up a self-hosted Temporal server.

## Quick Start (Automated)

```bash
./scripts/setup-temporal.sh
```

This starts Temporal at `localhost:7233` with Web UI at `http://localhost:8080`.

---

## Manual Steps (Reference)

### 1. Clone and Start

```bash
git clone https://github.com/temporalio/docker-compose.git temporal-docker
cd temporal-docker
docker compose up -d
```

### 2. Install CLI

```bash
# macOS
brew install temporal

# Linux
curl -sSf https://temporal.download/cli.sh | sh
```

### 3. Create Namespace

```bash
temporal operator namespace create confidential-workflow-poc
```

### 4. Verify

```bash
temporal workflow list --namespace confidential-workflow-poc
```

## Cleanup

```bash
cd temporal-docker
docker compose down -v
```

## Next Steps

- [04-enclave-development.md](./04-enclave-development.md) - Develop the enclave application
