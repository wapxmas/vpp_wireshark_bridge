# Contribution Guidelines

Thank you for your interest in our project! We welcome any help from the community, whether it's fixing bugs, adding new features, or improving documentation.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Questions and Suggestions](#questions-and-suggestions)
  - [Bug Reports](#bug-reports)
- [Change Contribution Process](#change-contribution-process)
  - [Creating a Fork](#creating-a-fork)
  - [Creating a Branch](#creating-a-branch)
  - [Making Changes](#making-changes)
  - [Submitting a Pull Request](#submitting-a-pull-request)
- [Code Style](#code-style)
  - [Python](#python)
  - [C (VPP Plugin)](#c-vpp-plugin)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

## Code of Conduct

This project adheres to the [Contributor Code of Conduct](CODE_OF_CONDUCT_EN.md). By participating in the project, you agree to abide by its terms.

## Getting Started

### Questions and Suggestions

For questions and suggestions, use [Issues](https://github.com/wapxmas/vpp_wireshark_bridge/issues) with appropriate labels. Before creating a new issue, please check that a similar question or suggestion is not already being discussed.

### Bug Reports

For bug reports, use [Issues](https://github.com/wapxmas/vpp_wireshark_bridge/issues) with the "bug" label. A good bug report should include:

1. A brief description of the problem
2. Steps to reproduce the bug
3. Expected behavior
4. Actual behavior
5. Versions of software used (VPP, Wireshark, Python)
6. Logs or screenshots, if applicable

## Change Contribution Process

### Creating a Fork

1. Create a fork of the repository on GitHub.
2. Clone your fork to your local machine:
   ```bash
   git clone https://github.com/your-username/vpp_wireshark_bridge.git
   cd vpp_wireshark_bridge
   ```
3. Add the original repository as upstream:
   ```bash
   git remote add upstream https://github.com/wapxmas/vpp_wireshark_bridge.git
   ```

### Creating a Branch

Create a separate branch for your changes:

```bash
git checkout -b feature/feature-name
# or for bug fixes
git checkout -b fix/fix-name
```

### Making Changes

1. Make the necessary changes to the code.
2. Follow the project's code style (see below).
3. Add tests if necessary.
4. Update documentation if required.
5. Ensure your code passes all tests.

### Submitting a Pull Request

1. Commit your changes:
   ```bash
   git add .
   git commit -m "Brief description of changes"
   ```
2. Push changes to your fork:
   ```bash
   git push origin feature/feature-name
   ```
3. Create a Pull Request on GitHub.
4. In the Pull Request description, indicate:
   - What exactly has been changed
   - Why these changes are necessary
   - How to verify the functionality
5. Wait for review and feedback from the project maintainers.

## Code Style

### Python

- Follow [PEP 8](https://pep8.org/) for code style
- Use docstrings to document functions and classes
- Prefer type hints to improve readability
- Maximum line length - 100 characters
- Use snake_case for variables and functions
- Use CamelCase for class names

Example:

```python
def process_packet(packet: bytes, interface_name: str) -> bool:
    """
    Processes an incoming packet.
    
    Args:
        packet: Binary packet data
        interface_name: Interface name
        
    Returns:
        True if the packet was processed successfully, otherwise False
    """
    # Function code
    return True
```

### C (VPP Plugin)

- Follow the VPP code style for plugins
- Use 2-space indentation
- Use snake_case for function and variable names
- Add comments for complex code sections
- Document public API functions

## Testing

- Add unit tests for new code
- For Python, use pytest
- Ensure your changes don't break existing functionality

## Documentation

- Update README.md if you add new features
- Add docstrings to all public functions
- If you add new commands or parameters, update the corresponding documentation sections

## License

By contributing to the project, you agree that your code will be licensed under the [Apache License 2.0](LICENSE-2.0.txt).

---

Thank you for contributing to the VPP to Wireshark Bridge project! 