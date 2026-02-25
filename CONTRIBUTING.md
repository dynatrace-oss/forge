# Contributing to FORGE

Thank you for your interest in contributing to FORGE!

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Podman (for container sandbox tests)
- Git

### Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/dynatrace-oss/forge.git
   cd forge
   ```

2. **Install dependencies**:
   ```bash
   uv sync
   ```

3. **Run quality gates**:
   ```bash
   uv run ruff check src/forge/ tests/ scripts/
   uv run python -m mypy src/forge/ --strict
   uv run pytest tests/ -x -q
   ```

## How to Contribute

- **Report bugs** — open an [issue](https://github.com/dynatrace-oss/forge/issues)
- **Suggest features** — open an issue describing the problem and proposed solution
- **Submit code** — fix bugs or implement new features via a pull request
- **Improve documentation** — fix inaccuracies or add missing context

## Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make focused changes with tests for new functionality.

3. Ensure all quality gates pass before opening a PR:
   ```bash
   uv run ruff check src/forge/ tests/ scripts/
   uv run python -m mypy src/forge/ --strict
   uv run pytest tests/ -x -q
   ```

4. Open a pull request with a clear title and description referencing any related issues.

5. Maintainers will review your PR. Address any feedback and keep your branch up-to-date with `main`.

## Coding Standards

- Full type annotations everywhere; use `X | None` (not `Optional[X]`)
- Pydantic `BaseModel` for data models, `StrEnum` for enumerations
- LLM calls through LiteLLM only
- No inline comments explaining *what* code does — only *why* (non-obvious constraints or workarounds)

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <subject>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`

## Security Issues

**Do not report security vulnerabilities through public GitHub issues.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

By contributing to FORGE, you agree that your contributions will be licensed under the [proprietary license](LICENSE).
