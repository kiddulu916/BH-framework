import os
import shutil
import tempfile
import pytest
import requests_mock
import run_passive_recon
from run_passive_recon import main as run_passive_recon_main

# Constants for test
TEST_TARGET = "testdomain.com"
TEST_STAGE = "passive_recon"
TEST_OUTPUTS = f"/outputs/{TEST_STAGE}/{TEST_TARGET}"
TEST_PARSED = os.path.join(TEST_OUTPUTS, "parsed")

def create_raw_file(path, content="testdata\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

@pytest.fixture(scope="function")
def temp_outputs(monkeypatch):
    temp_dir = tempfile.mkdtemp()
    monkeypatch.setenv("OUTPUTS_ROOT", temp_dir)
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture(scope="function")
def mock_env(monkeypatch):
    monkeypatch.setenv("BACKEND_API_URL", "http://mock-backend/api/v1/results/passive-recon")
    monkeypatch.setenv("BACKEND_JWT_TOKEN", "testtoken")
    # Set tool paths to echo for fast test
    monkeypatch.setenv("AMASS_PATH", "echo")
    monkeypatch.setenv("SUBFINDER_PATH", "echo")
    monkeypatch.setenv("ASSETFINDER_PATH", "echo")
    monkeypatch.setenv("GAU_PATH", "echo")
    monkeypatch.setenv("SUBLIST3R_PATH", "echo")
    monkeypatch.setenv("CERO_PATH", "echo")
    monkeypatch.setenv("WAYBACKURLS_PATH", "echo")

def mock_all_runners(monkeypatch):
    def fake_runner_sublist3r(target, output_dir):
        raw_path = os.path.join(output_dir, f"sublist3r_{target}.txt")
        create_raw_file(raw_path, "sub1.test.com\nsub2.test.com\n")
        return ["sub1.test.com", "sub2.test.com"]
    def fake_runner_amass(target, output_dir):
        raw_path = os.path.join(output_dir, f"amass_{target}.txt")
        create_raw_file(raw_path, "sub3.test.com\n")
        return {"subdomains": ["sub3.test.com"]}
    def fake_runner_subfinder(target, output_dir):
        raw_path = os.path.join(output_dir, f"subfinder_{target}.json")
        create_raw_file(raw_path, "sub4.test.com\n")
        return ["sub4.test.com"]
    def fake_runner_assetfinder(target, output_dir):
        raw_path = os.path.join(output_dir, f"assetfinder_{target}.txt")
        create_raw_file(raw_path, "sub5.test.com\n")
        return ["sub5.test.com"]
    def fake_runner_gau(target, output_dir):
        raw_path = os.path.join(output_dir, f"gau_{target}.json")
        create_raw_file(raw_path, "sub6.test.com\n")
        return ["sub6.test.com"]
    def fake_runner_cero(target, output_dir):
        raw_path = os.path.join(output_dir, f"cero_{target}.txt")
        create_raw_file(raw_path, "sub7.test.com\n")
        return {"subdomains": ["sub7.test.com"]}
    def fake_runner_waybackurls(target, output_dir):
        raw_path = os.path.join(output_dir, f"waybackurls_{target}.txt")
        create_raw_file(raw_path, "sub8.test.com\n")
        return ["sub8.test.com"]
    monkeypatch.setattr(run_passive_recon, "run_sublist3r", fake_runner_sublist3r)
    monkeypatch.setattr(run_passive_recon, "run_amass", fake_runner_amass)
    monkeypatch.setattr(run_passive_recon, "run_subfinder", fake_runner_subfinder)
    monkeypatch.setattr(run_passive_recon, "run_assetfinder", fake_runner_assetfinder)
    monkeypatch.setattr(run_passive_recon, "run_gau", fake_runner_gau)
    monkeypatch.setattr(run_passive_recon, "run_cero", fake_runner_cero)
    monkeypatch.setattr(run_passive_recon, "run_waybackurls", fake_runner_waybackurls)

def test_tools_successful_scan(monkeypatch, temp_outputs, mock_env):
    monkeypatch.setattr("sys.argv", ["run_passive_recon.py", "--target", TEST_TARGET, "--stage", TEST_STAGE])
    orig_join = os.path.join
    monkeypatch.setattr("os.path.join", lambda *args: orig_join(temp_outputs, *args[1:]) if args[0] == "/outputs" else orig_join(*args))
    monkeypatch.setattr(run_passive_recon, "save_raw_to_db", lambda *a, **kw: True)
    monkeypatch.setattr(run_passive_recon, "save_parsed_to_db", lambda *a, **kw: True)
    mock_all_runners(monkeypatch)
    run_passive_recon_main()
    assert os.path.exists(os.path.join(temp_outputs, TEST_STAGE, TEST_TARGET, "parsed", "all_subdomains.json"))

def test_error_handling(monkeypatch, temp_outputs, mock_env):
    monkeypatch.setattr("sys.argv", ["run_passive_recon.py", "--target", TEST_TARGET, "--stage", TEST_STAGE])
    # Patch only amass to raise, others to return dummy data
    monkeypatch.setattr(run_passive_recon, "run_amass", lambda *a, **kw: (_ for _ in ()).throw(Exception("amass fail")))
    monkeypatch.setattr(run_passive_recon, "run_sublist3r", lambda *a, **kw: ["sub1.test.com"])
    monkeypatch.setattr(run_passive_recon, "run_subfinder", lambda *a, **kw: ["sub2.test.com"])
    monkeypatch.setattr(run_passive_recon, "run_assetfinder", lambda *a, **kw: ["sub3.test.com"])
    monkeypatch.setattr(run_passive_recon, "run_gau", lambda *a, **kw: ["sub4.test.com"])
    monkeypatch.setattr(run_passive_recon, "run_cero", lambda *a, **kw: {"subdomains": ["sub5.test.com"]})
    monkeypatch.setattr(run_passive_recon, "run_waybackurls", lambda *a, **kw: ["sub6.test.com"])
    orig_join = os.path.join
    monkeypatch.setattr("os.path.join", lambda *args: orig_join(temp_outputs, *args[1:]) if args[0] == "/outputs" else orig_join(*args))
    monkeypatch.setattr(run_passive_recon, "save_raw_to_db", lambda *a, **kw: True)
    monkeypatch.setattr(run_passive_recon, "save_parsed_to_db", lambda *a, **kw: True)
    run_passive_recon_main()
    assert os.path.exists(os.path.join(temp_outputs, TEST_STAGE, TEST_TARGET, "parsed", "all_subdomains.json"))

def test_backend_submission(monkeypatch, temp_outputs, mock_env):
    monkeypatch.setattr("sys.argv", ["run_passive_recon.py", "--target", TEST_TARGET, "--stage", TEST_STAGE])
    orig_join = os.path.join
    monkeypatch.setattr("os.path.join", lambda *args: orig_join(temp_outputs, *args[1:]) if args[0] == "/outputs" else orig_join(*args))
    called = {"raw": 0, "parsed": 0}
    def fake_raw(*a, **kw):
        called["raw"] += 1
        return True
    def fake_parsed(*a, **kw):
        called["parsed"] += 1
        return True
    monkeypatch.setattr(run_passive_recon, "save_raw_to_db", fake_raw)
    monkeypatch.setattr(run_passive_recon, "save_parsed_to_db", fake_parsed)
    mock_all_runners(monkeypatch)
    run_passive_recon_main()
    assert called["raw"] > 0 and called["parsed"] > 0

def test_accessibility_of_scan_results(monkeypatch, temp_outputs, mock_env):
    monkeypatch.setattr("sys.argv", ["run_passive_recon.py", "--target", TEST_TARGET, "--stage", TEST_STAGE])
    orig_join = os.path.join
    monkeypatch.setattr("os.path.join", lambda *args: orig_join(temp_outputs, *args[1:]) if args[0] == "/outputs" else orig_join(*args))
    monkeypatch.setattr(run_passive_recon, "save_raw_to_db", lambda *a, **kw: True)
    monkeypatch.setattr(run_passive_recon, "save_parsed_to_db", lambda *a, **kw: True)
    mock_all_runners(monkeypatch)
    run_passive_recon_main()
    parsed_dir = os.path.join(temp_outputs, TEST_STAGE, TEST_TARGET, "parsed")
    expected = [
        "sublist3r_subdomains.json",
        "amass_results.json",
        "subfinder_subdomains.json",
        "assetfinder_subdomains.json",
        "gau_subdomains.json",
        "cero_results.json",
        "waybackurls_subdomains.json",
        "all_subdomains.json"
    ]
    for fname in expected:
        assert os.path.exists(os.path.join(parsed_dir, fname)) 