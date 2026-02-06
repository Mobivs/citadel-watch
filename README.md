# Citadel Archer

**Version**: 0.2.2 (Phase 1 - Foundation)

AI-centric defensive security platform for Windows 10/11. Proactive protection that acts first, informs after.

## Philosophy

> "If we're asking 'Should I block this malware?' we've already FAILED."

Citadel Archer is an AI-powered defensive security platform that protects individuals from persistent cyber threats. The AI acts autonomously (within your chosen security level), explains decisions clearly, and puts you back in control of your digital life.

## Project Status

- **Current Phase**: Phase 1 - Foundation (Months 1-3)
- **Platform**: Windows 10/11
- **Status**: 🚧 In Development

## Features (Phase 1)

- **Guardian Agent**: Real-time file and process monitoring
- **Dashboard**: Dark glassmorphic UI with system status
- **Vault**: Encrypted password manager (AES-256 + SQLCipher)
- **Security Levels**: Observer, Guardian, Sentinel (you choose)
- **Audit Logging**: Immutable forensic logs

## Quick Start

### Prerequisites

- Windows 10/11
- Python 3.11 or higher
- Git

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd citadel-archer
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   cd frontend
   npm install
   cd ..
   ```

4. **Run the application**:
   ```bash
   python -m citadel_archer
   ```

## Project Structure

```
citadel-archer/
├── .claude/                 # Claude Code configuration & PRD system
├── docs/                    # PRD, ADRs, checklists
├── src/
│   └── citadel_archer/      # Main Python package
│       ├── guardian/        # Local machine protection
│       ├── vault/           # Password manager
│       ├── watchtower/      # Central monitoring
│       ├── intel/           # Threat intelligence (Phase 2)
│       ├── dashboard/       # Web UI backend
│       └── core/            # Shared utilities
├── frontend/                # React + TypeScript UI
├── tests/                   # Unit and integration tests
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Development

### Running Tests

```bash
pytest tests/
```

### Building Desktop App

```bash
python -m PyInstaller citadel_archer.spec
```

## Security Levels

- **Observer**: AI monitors and alerts, no autonomous actions
- **Guardian**: AI automatically responds to known threats (default)
- **Sentinel**: AI has maximum autonomy within ethical bounds

## Documentation

- **PRD**: [docs/PRD.md](docs/PRD.md) - Complete product requirements
- **ADRs**: [docs/adr/](docs/adr/) - Architecture decision records
- **Checklist**: [docs/checklists/phase-1-compliance.md](docs/checklists/phase-1-compliance.md)

## License

Proprietary - See LICENSE file

## Contact

For questions or support, open an issue on the repository.

---

**Built with care to protect the innocents. 🛡️**
