# Contributing to PDF XSS Checker

Thank you for considering contributing to `pdf-xss-checker`! We welcome your contributions to make this project even better.

## Table of Contents

- [How Can I Contribute?](#how-can-i-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Branching and Commit Guidelines](#branching-and-commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [License](#license)

## How Can I Contribute?

There are several ways you can contribute to `pdf-xss-checker`:

*   **Report bugs:** If you find a bug, please open an issue.
*   **Suggest enhancements:** Have an idea for a new feature or an improvement? Let us know by opening an issue.
*   **Write code:** Fix bugs, implement new features, or improve existing ones by submitting pull requests.
*   **Improve documentation:** Help us improve our documentation, examples, and guides.

## Reporting Bugs

Before reporting a bug, please check the existing issues to see if it has already been reported. When reporting a bug, please include:

*   A clear and concise description of the bug.
*   Steps to reproduce the behavior.
*   Expected behavior.
*   Actual behavior.
*   Screenshots or error messages (if applicable).
*   Your environment (Node.js version, OS, `pdf-xss-checker` version).

## Suggesting Enhancements

When suggesting an enhancement, please include:

*   A clear and concise description of the suggested enhancement.
*   Why this enhancement would be useful.
*   Any alternative solutions you've considered.

## Development Setup

To set up your development environment, follow these steps:

1.  **Fork the repository** to your GitHub account.
2.  **Clone your forked repository** to your local machine:

    ```bash
    git clone https://github.com/YOUR_USERNAME/pdf-xss-checker.git
    ```
3.  **Navigate to the project directory**:

    ```bash
    cd pdf-xss-checker
    ```
4.  **Install dependencies**:

    ```bash
    npm install
    ```

## Coding Standards

We strive for consistent and readable code. Please adhere to the following guidelines:

*   **ESLint:** We use ESLint to enforce code style and catch potential errors. Please ensure your code passes ESLint checks.
*   **Naming Conventions:** Use camelCase for variables and functions, PascalCase for classes, and SCREAMING_SNAKE_CASE for constants.
*   **Comments:** Write clear and concise comments for complex logic or non-obvious code.
*   **Readability:** Prioritize code readability and simplicity.

## Branching and Commit Guidelines

*   **Branching:** Create a new branch for each feature or bug fix. Use descriptive branch names (e.g., `feature/add-new-detector`, `bugfix/fix-cli-issue`).
*   **Commit Messages:** Write clear, concise, and descriptive commit messages. Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification if possible (e.g., `feat: add new CLI option`, `fix: correct vulnerability detection logic`).

## Pull Request Process

1.  **Before submitting:** Ensure your code adheres to the [Coding Standards](#coding-standards) and passes all tests.
2.  **Open a Pull Request:** Submit your changes from your feature branch to the `main` branch of the original repository.
3.  **Provide a clear description:** In your pull request description, explain the changes you've made, why you've made them, and any relevant issue numbers.
4.  **Respond to feedback:** Be prepared to discuss your changes and address any feedback during the review process.
5.  **Tests:** If your changes introduce new features or fix bugs, please include relevant tests.

## License

By contributing to `pdf-xss-checker`, you agree that your contributions will be licensed under the MIT License, as specified in the `LICENSE` file.