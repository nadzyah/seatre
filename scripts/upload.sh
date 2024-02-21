#!/bin/bash
source venv/bin/activate
python3 -m build
poetry run twine check dist/*
poetry run twine upload --skip-existing dist/* --repository pypi
