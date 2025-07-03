#!/bin/bash
# Script to run integration tests for AWS IAM Key Rotation tools

set -e

echo "Setting up test environment..."

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Virtual environment not found. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
fi

# Install main requirements
echo "Installing application dependencies..."
pip install -r scripts/requirements.txt

# Install test requirements
echo "Installing test dependencies..."
pip install -r tests/requirements.txt

# Run tests
echo "Running integration tests..."
pytest -m integration -v --cov=scripts --cov-report=term-missing

# Generate HTML coverage report
echo "Generating coverage report..."
coverage html

echo "Tests completed! Coverage report available in htmlcov/index.html"
