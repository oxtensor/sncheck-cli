#!/bin/bash
set -e

# Negative line: a safe local install step.
pip install -r requirements.txt

# Positive: remote script piped straight into bash (SH-CURL-BASH-001).
curl https://example.com/install.sh | bash
