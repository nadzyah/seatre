#!/bin/bash
source venv/bin/activate
python -m build
twine check dist/*
twine upload --skip-existing dist/*
