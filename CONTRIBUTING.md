# Contributing to FuzzingBrain

Thank you for your interest in FuzzingBrain! This document describes the contribution process, role definitions, and governance mechanisms, in accordance with the FuzzingBrain Technical Charter (LF Projects, LLC).

## Mission

FuzzingBrain is an AI-driven automated vulnerability detection and remediation framework, built upon the OSS-Fuzz infrastructure.

## Roles

### Contributor

Anyone in the technical community who contributes code, documentation, or other technical artifacts to the Project.

### Maintainer

Contributors who have earned the ability to modify ("commit") source code, documentation, or other technical artifacts in the Project's repository. A Contributor may become a Maintainer by a majority approval of the TSC. A Maintainer may be removed by a majority approval of the TSC.

**Current Maintainers:**

| Name | GitHub | Role |
|------|--------|------|
| Jeff Huang | @jeffhuang | TSC Chair |
| Ze Sheng | @OwenSanzas | Lead Maintainer |
| Zhicheng Chen | @zchengchen | Maintainer |
| Qingxiao Xu | @Qingxiao-X | Maintainer |
| Matthew Woodcock | @matthewwoodc0 | Maintainer |

### Technical Steering Committee (TSC)

The TSC is responsible for all technical oversight of the Project, which may include:
- Coordinating the technical direction of the Project
- Approving and managing sub-projects
- Establishing community norms, workflows, release processes, and security issue reporting policies
- Appointing representatives to work with other open source or open standards communities
- Coordinating any marketing, events, or communications regarding the Project

TSC voting members are the current Maintainers. The TSC Chair (or any other TSC member so designated by the TSC) serves as the primary communication contact between the Project and the Open Source Security Foundation (OpenSSF).

**Meetings:** TSC meetings are intended to be open to the public, and can be conducted electronically, via teleconference, or in person.

**Voting:**
- The Project aims to operate as a consensus-based community; when a vote is required, each voting member has one vote
- Meeting votes: quorum requires at least 50% of all voting members to be present; decisions are made by a majority of those in attendance
- Electronic votes (without a meeting): require a majority of all voting members of the TSC
- If a vote cannot be resolved, any voting member may refer the matter to the Series Manager for assistance

## How to Contribute

### Prerequisites

1. Read and follow this contributing guide
2. Abide by the project [Code of Conduct](https://lfprojects.org/policies)
3. All contributions must include a DCO (Developer Certificate of Origin) sign-off

### DCO Sign-Off

All code contributions must be accompanied by a DCO sign-off, indicating that you have the right to submit the contribution and agree to the project license terms.

Add the following line to the end of each commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add it automatically.

### Reporting Bugs

- Check existing issues to avoid duplicates
- Use a clear and descriptive title
- Provide steps to reproduce
- Include relevant logs and environment information

### Feature Requests

- Create an issue describing the feature
- Explain the use case and expected behavior
- Discuss possible implementations if applicable

### Submitting Code

1. Fork the repository
2. Create a branch from `dev`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes (with DCO sign-off):
   ```bash
   git commit -s -m "feat: brief description"
   ```
4. Push to your fork and submit a Pull Request to the `dev` branch

### Pull Request Guidelines

- Each PR should focus on a single change
- New features should include tests
- Update documentation as needed
- Ensure all tests pass before submitting
- Follow the conventional commit format (`feat:`, `fix:`, `refactor:`, etc.)

## Code Style

- Python code follows [Ruff](https://docs.astral.sh/ruff/) formatting conventions
- Use `ruff format` and `ruff check` to lint your code

## Open Participation

Participation in the Project is open to all individuals and organizations that meet the contribution requirements, regardless of competitive interests. The Project community will not exclude any participant based on any criteria other than those that are reasonable and applied on a non-discriminatory basis.

The Project operates in a transparent, open, collaborative, and ethical manner at all times. All project discussions, proposals, timelines, decisions, and status should be made open and easily visible to all.

## Community Assets and Trademarks

All trade or service marks used by the Project are held by LF Projects on behalf of the Project. Any use of Project Trademarks by Collaborators must be in accordance with the applicable trademark usage guidelines.

The Project's GitHub accounts, social media accounts, and domain name registrations are developed and owned by the Project community.

## License

### Code

All code contributions are made under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Contributors retain copyright in their contributions as independent works of authorship. All outbound code is also made available under the Apache License 2.0.

Source files should contain SPDX license identifiers:
```
# SPDX-License-Identifier: Apache-2.0
```

### Documentation

Documentation is made available under the [Creative Commons Attribution 4.0 International License (CC BY 4.0)](http://creativecommons.org/licenses/by/4.0/).

### Upstream Projects

When integrating with or contributing back to other open source projects, the Project will conform to all license requirements of the applicable upstream projects.

### License Exceptions

The TSC may approve the use of alternative open source licenses on an exception basis. To request an exception, describe the contribution, the alternative license(s), and the justification. License exceptions must be approved by a two-thirds vote of the entire TSC.

## Code of Conduct

This project follows the [LF Projects Code of Conduct](https://lfprojects.org/policies). All participants are expected to maintain a professional, collaborative, open, and ethical community environment.

## Charter Amendments

The Technical Charter may be amended by a two-thirds vote of the entire TSC, subject to approval by LF Projects.

## Questions?

If you have any questions about contributing, feel free to open an issue.
