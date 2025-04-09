# Pandacea Project

## Project Structure

The project is organized into the following components:

- **backend/**: Core Rust implementation of the Pandacea Model Context Protocol
  - Contains the main Rust codebase with implementation details
  - Includes Cargo configuration files for Rust dependencies

- **frontend/**: UI components for Pandacea
  - React-based user interface
  - TypeScript implementation for type safety

- **sdk/**: Developer kit for integrating with Pandacea
  - TypeScript SDK for easy integration with Pandacea services
  - Provides client libraries for API communication

- **proto/**: Protocol definition files
  - Contains protobuf definitions for the MCP protocol
  - Source of truth for API contracts

- **docs/**: Project documentation
  - Architecture diagrams
  - Design specifications
  - Usage guides

## Getting Started

### Backend Development

```
cd backend
cargo build
cargo test
```

### Frontend Development

```
cd frontend
npm install
npm start
```

### SDK Development

```
cd sdk
npm install
npm run build
```

## Contributing

Please see the [contributing guide](docs/contributing.md) for details on how to contribute to the project.

## License

This project is licensed under the terms specified in [license.md](docs/license.md).

## An Open Framework for Consent-Driven Data Ecosystems

Pandacea is an open framework for building consent-driven, ethically-compensated, and agent-aware data ecosystems that places privacy, consent, and reciprocity at the foundation of how data flows.

For a comprehensive overview of Pandacea's vision, architecture, and technical specifications, please read our [Whitepaper](pandacea_whitepaper.md).

## Vision

As agentic AI systems and humanoid robotics scale, entire industries are already entering hiring freezes, and soon, job reductions. Within the next 3 to 5 years, we face a critical economic transition. When machines can do nearly everything humans can, what is left for people to contribute?

Pandacea exists to answer that question. We believe the future of human value lies in consented, compensated data contribution.

Billions, and eventually trillions, of agent-to-agent transactions will power our global systems. Behind each valuable dataset is a person — someone whose preferences, behaviors, creations, or environment shaped the inputs that made AI smarter. Their participation should earn them a stake in the AI economy.

We envision a world where:

Your personal agent negotiates with AI systems on your behalf

You get paid for sharing valuable, use-ready data, whether passively or through innovative tools you build

New job titles like “Data Provider” and “Loop Creator” become real paths to income

Young people, raised as native AI builders, learn to generate useful data through custom agents and apps — and are rewarded from the start

This is how we survive the transition, not by resisting AI, but by ensuring that the value it creates flows back to the people who power it.

Pandacea is building the infrastructure to make that possible. We’re not just optimizing computation. We’re reimagining compensation.

## Core Architecture

Pandacea's architecture consists of five key components designed to enforce consent and context at the point of data generation:

1. **Model Context Protocol (MCP)**: A flexible, open protocol for requesting and exchanging data with clear purpose, identity, compensation, trust tier, and required permissions.

2. **Consent Manager + Consent Genome**: A local agent running on the user's edge device that interprets incoming requests against the user's evolving Consent Genome.

3. **Sentinel Agent**: Co-located with the Consent Manager, acting as an active guardrail to monitor for suspicious activity and enforce advanced threat response logic.

4. **Cloud Coordination Layer**: A minimal, stateless service facilitating the discovery of MCP endpoints and routing requests between participants.

5. **Audit & Integrity Layer**: Each edge device maintains a tamper-aware local audit log to ensure verifiability across participants without exposing raw data.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical specifications.

## Current Status

Pandacea is currently in the early development phase (Phase 0: Infrastructure Groundwork). We are establishing foundational elements, defining protocols, and building our community. See our [ROADMAP.md](ROADMAP.md) for development phases and milestones.

## Getting Started

### Prerequisites

<!-- Add specific technical prerequisites as they become available -->
- Git
- Node.js (version X.X.X or later)
- Other dependencies will be listed as they are defined

### Installation

```bash
# Clone the repository
git clone https://github.com/pandacea/pandacea.git
cd pandacea

# Install dependencies
npm install

# Start development environment
npm run dev
```

### Examples

<!-- Add examples as they become available -->
Basic examples will be provided in the `examples/` directory as components are developed.

## Contributing

We welcome contributions from developers, designers, researchers, ethicists, and anyone passionate about creating ethical data ecosystems. See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to contribute.

## Governance & Participation

Pandacea practices progressive decentralization, starting with structured initial stewardship and transitioning to community control over time. Governance influence is earned through contributions to the Access Commons. Working Groups manage specific governance areas with open proposals and transparent decision-making.

Learn more about our governance model in the [GOVERNANCE.md](GOVERNANCE.md) document.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. All participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

This project is licensed under the [AGPL-3.0](LICENSE.md) license - see the [LICENSE.md](LICENSE.md) file for details.

## Contact

pandaceaproject@gmail.com

## Acknowledgments

- All contributors and community members
- Organizations and individuals who have shared knowledge and resources
- The broader open-source community

---

*The future of data will be shaped by the interactions between people and intelligent agents. Pandacea is how we ensure that future remains grounded in human values.*
