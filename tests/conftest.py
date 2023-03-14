"""
conftest
"""

import pytest
import os
import importlib  
import sys


current_path = os.path.dirname(os.path.realpath(__file__))
from main.loki import Loki

@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    monkeypatch.setenv("HOST", "https://test.org")
    monkeypatch.setenv("CLIENT_ID", "abcdef")
    monkeypatch.setenv("CLIENT_SECRET", "abcdef")

@pytest.fixture(scope="session")
def test_loki():
    return Loki("https://test.org", "abcdef", "abcdef")
