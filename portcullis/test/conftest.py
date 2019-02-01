"""
conftest.py

Configures the pytest-flask environment
"""
import pytest
from portcullis import portcullis

@pytest.fixture
def app():
    app = portcullis()
    return app

