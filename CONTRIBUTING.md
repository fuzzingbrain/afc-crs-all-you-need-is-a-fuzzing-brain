# Contributing to FuzzingBrain

Thank you for your interest in contributing to FuzzingBrain! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your contribution

## Development Setup

```bash
cd crs
LOCAL_TEST=1 go run ./cmd/server/main.go
```

For detailed setup instructions, see the [README](README.md).

## How to Contribute

### Reporting Bugs

- Check existing issues to avoid duplicates
- Use a clear and descriptive title
- Provide steps to reproduce the issue
- Include relevant logs and environment details

### Suggesting Features

- Open an issue describing the feature
- Explain the use case and expected behavior
- Discuss the implementation approach if possible

### Submitting Changes

1. Create a branch from `dev`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit:
   ```bash
   git commit -m "Brief description of changes"
   ```

3. Push to your fork and submit a Pull Request to the `dev` branch

### Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting

## Code Style

- Go code should follow standard Go conventions (`gofmt`)
- Python code should follow PEP 8

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Questions?

Feel free to open an issue if you have any questions about contributing.
