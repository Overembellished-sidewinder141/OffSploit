import pytest
from unittest.mock import patch, MagicMock
from offsploit.session_db import SessionManager
from web.web_app import app, handle_run_pipeline, socketio, get_history, get_session_steps

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_api_history(client):
    """Test if /api/history endpoint works and returns list."""
    with patch("web.web_app.session_manager.get_all_sessions", return_value=[{"id": "session1", "status": "completed"}]):
        response = client.get("/api/history")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == "session1"

def test_api_session_steps(client):
    """Test if /api/session/<id>/steps endpoint returns steps."""
    with patch("web.web_app.session_manager.get_steps", return_value=[{"id": 1, "status": "success"}]):
        response = client.get("/api/session/session1/steps")
        assert response.status_code == 200
        data = response.get_json()
        assert data["session_id"] == "session1"
        assert len(data["steps"]) == 1

@patch("web.web_app.emit")
@patch("web.web_app.AsyncOffSploitPipeline")
@patch("web.web_app.session_manager")
def test_handle_run_pipeline_triggers_async(mock_session_manager, mock_pipeline_class, mock_emit, client):
    """Test handle_run_pipeline creates task and starts thread."""
    mock_pipeline_instance = MagicMock()
    mock_pipeline_class.return_value = mock_pipeline_instance
    mock_session_manager.create_session.return_value = "mock_session_id"
    mock_session_manager.log_step.return_value = 1
    
    # Run the pipeline handler
    data = {
        "nmap_path": "test.xml",
        "lhost": "127.0.0.1",
        "rhost": "10.0.0.1",
        "lport": "4444"
    }
    
    handle_run_pipeline(data)
    
    # Emit should be called with task_started
    mock_emit.assert_called_with("task_started", {"task_id": mock_emit.call_args[0][1]["task_id"]})
    assert len(mock_emit.call_args_list) >= 1
