# Contributing

Thanks for your interest in contributing! This project is part of the
AI Security Projects series, a collection of zero-dependency security tools
for engineers and teams who want production-grade security without the
enterprise price tag.

## Quick start for contributors

```bash
# 1. Fork on GitHub, then clone your fork
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# 2. Create a feature branch
git checkout -b feature/your-idea

# 3. Install dev dependencies (if any are listed)
pip install -r requirements.txt

# 4. Make your changes
# 5. Run the self-tests
python <main_file>.py samples/

# 6. Commit with a descriptive message
git commit -m "feat: short description of what you added"

# 7. Push and open a PR
git push origin feature/your-idea
```

## What to contribute

**Great first contributions:**
- Add a new detection rule (SAST, Cloud Misconfig, WAF Bypass Lab)
- Add a new compliance framework JSON (Compliance Gap Analyzer)
- Add test cases to the benchmark suite (Prompt Injection Proxy)
- Improve the HTML dashboards (CSS, accessibility, dark mode tweaks)
- Translate the README to another language
- Add a GitHub Actions workflow, Dockerfile improvement, or CI check

**Larger contributions** (open an issue first to discuss):
- New output formats (SARIF, CSV, PDF)
- New integrations (Splunk, Datadog, Elastic)
- LLM-powered remediation suggestions
- Performance optimizations

## Pull request checklist

- [ ] Code runs without errors on Python 3.8+
- [ ] New rules / frameworks include at least 1 test case in `samples/`
- [ ] README is updated if you added a new feature or flag
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] No secrets, API keys, or PII in commits
- [ ] License header preserved in modified files

## Code style

- Python 3.8+ compatible
- Prefer stdlib over external dependencies (big value prop of this suite)
- Use `dataclasses` for result structures
- Regex patterns should have inline comments explaining what they catch
- HTML reports should work offline (no CDN dependencies)

## Reporting issues

Bug reports are welcome. Please include:
- Python version (`python --version`)
- OS and architecture
- Exact command you ran
- Full error message / traceback
- Expected behavior

## Code of Conduct

Be kind. Be patient. Assume good faith. Don't be a jerk.

## License

By contributing, you agree that your contributions will be licensed under
the project's MIT License.
