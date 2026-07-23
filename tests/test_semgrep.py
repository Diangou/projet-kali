# test_semgrep.py
import pytest
from unittest.mock import patch, MagicMock
import subprocess

@pytest.fixture
def mock_subprocess_run():
    with patch('subprocess.run') as mock:
        yield mock

def test_run_semgrep_success(mock_subprocess_run):
    # Setup
    target_url = "http://localhost:3000/"
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "No issues found\n"
    mock_result.stderr = ""
    mock_subprocess_run.return_value = mock_result
    
    # Execute
    from vuln_scanner.semgrep import run_semgrep
    result = run_semgrep(target_url)
    
    # Verify
    assert result is True
    mock_subprocess_run.assert_called_once_with(
        ["semgrep", "--config=p/ci", target_url],
        capture_output=True,
        text=True
    )

def test_run_semgrep_failure(mock_subprocess_run):
    # Setup
    target_url = "http://localhost:3000/"
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "Error running Semgrep"
    mock_subprocess_run.return_value = mock_result
    
    # Execute
    from vuln_scanner.semgrep import run_semgrep
    result = run_semgrep(target_url)
    
    # Verify
    assert result is False
    mock_subprocess_run.assert_called_once_with(
        ["semgrep", "--config=p/ci", target_url],
        capture_output=True,
        text=True
    )

def test_run_semgrep_with_issues(mock_subprocess_run):
    # Setup
    target_url = "http://localhost:3000/"
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "WARNING: Found security issue\n"
    mock_result.stderr = ""
    mock_subprocess_run.return_value = mock_result
    
    # Execute
    from vuln_scanner.semgrep import run_semgrep
    result = run_semgrep(target_url)
    
    # Verify
    assert result is True
    mock_subprocess_run.assert_called_once_with(
        ["semgrep", "--config=p/ci", target_url],
        capture_output=True,
        text=True
    )