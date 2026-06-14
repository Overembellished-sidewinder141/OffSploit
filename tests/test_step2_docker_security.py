#!/usr/bin/env python3
"""
OffSploit - Adım 2 Testleri: Docker Sandbox Güvenlik Sıkılaştırma
===================================================================
"""

from unittest import mock

import pytest


# ─────────────────────────────────────────────
# Test 1: Güvenlik sabitleri doğru tanımlı
# ─────────────────────────────────────────────

def test_security_constants_defined():
    """DockerSandbox sınıfı zorunlu güvenlik sabitlerini içermeli."""
    from offsploit.docker_sandbox import DockerSandbox

    assert DockerSandbox._SECURITY_CAP_DROP == ["ALL"]
    assert DockerSandbox._SECURITY_NETWORK_MODE == "none"
    assert DockerSandbox._SECURITY_OPT == ["no-new-privileges:true"]
    assert DockerSandbox._SECURITY_PIDS_LIMIT == 100


# ─────────────────────────────────────────────
# Test 2: _create_container_kwargs içerik kontrolü
# ─────────────────────────────────────────────

def test_create_container_kwargs_has_security_params():
    """_create_container_kwargs metodu tüm güvenlik parametrelerini içermeli."""
    from offsploit.docker_sandbox import DockerSandbox

    sandbox = DockerSandbox(memory_limit="256m", cpu_limit=0.5, timeout=30)
    kwargs = sandbox._create_container_kwargs("gcc:latest", "gcc /tmp/test.c -o /tmp/test")

    # Zorunlu güvenlik parametreleri
    assert kwargs["cap_drop"] == ["ALL"], "cap_drop ALL eksik!"
    assert kwargs["network_mode"] == "none", "network_mode none eksik!"
    assert kwargs["security_opt"] == ["no-new-privileges:true"], "no-new-privileges eksik!"
    assert kwargs["pids_limit"] == 100, "pids_limit eksik!"

    # Diğer parametreler
    assert kwargs["image"] == "gcc:latest"
    assert kwargs["mem_limit"] == "256m"
    assert kwargs["detach"] is True
    assert kwargs["stdin_open"] is False
    assert kwargs["tty"] is False


# ─────────────────────────────────────────────
# Test 3: Container create çağrısı güvenlik parametreleriyle yapılır
# ─────────────────────────────────────────────

def test_container_create_called_with_security_params():
    """client.containers.create() çağrısı cap_drop=ALL ile yapılmalı."""
    from offsploit.docker_sandbox import DockerSandbox

    sandbox = DockerSandbox()

    # Mock Docker client
    mock_client = mock.MagicMock()
    mock_container = mock.MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.return_value = b"OK"
    mock_client.containers.create.return_value = mock_container

    sandbox._client = mock_client
    sandbox._active_containers = 0

    # _run_container çağır
    exit_code, stdout, stderr = sandbox._run_container(
        image="gcc:latest",
        command="gcc /tmp/test.c -o /tmp/test",
        source_code="#include <stdio.h>\nint main() { return 0; }",
        source_file="/tmp/test.c",
    )

    # create çağrısını al ve parametreleri kontrol et
    create_call = mock_client.containers.create.call_args
    call_kwargs = create_call[1] if create_call[1] else create_call[0]

    # kwargs olarak çağrıldıysa (** spread)
    if isinstance(call_kwargs, dict) and "cap_drop" in call_kwargs:
        assert call_kwargs["cap_drop"] == ["ALL"]
        assert call_kwargs["network_mode"] == "none"
        assert call_kwargs["security_opt"] == ["no-new-privileges:true"]
        assert call_kwargs["pids_limit"] == 100
    else:
        # Positional veya keyword argüman olarak gelmiş olabilir
        # create(**kwargs) çağrısı — tüm parametreler keyword olmalı
        all_kwargs = {**create_call.kwargs}
        assert all_kwargs.get("cap_drop") == ["ALL"], f"cap_drop eksik! Çağrı: {create_call}"
        assert all_kwargs.get("network_mode") == "none"
        assert all_kwargs.get("security_opt") == ["no-new-privileges:true"]
        assert all_kwargs.get("pids_limit") == 100


# ─────────────────────────────────────────────
# Test 4: ImageNotFound sonrası ikinci create de güvenli
# ─────────────────────────────────────────────

def test_image_not_found_retry_also_secure():
    """ImageNotFound durumunda ikinci create çağrısı da güvenlik parametreleri içermeli."""
    from offsploit.docker_sandbox import DockerSandbox

    sandbox = DockerSandbox()

    # Docker SDK modülünü mock'la
    mock_docker_module = mock.MagicMock()
    mock_client = mock.MagicMock()

    # İlk create ImageNotFound fırlatsın, ikincisi başarılı olsun
    mock_container = mock.MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.return_value = b"OK"

    image_not_found = type("ImageNotFound", (Exception,), {})
    mock_docker_module.errors.ImageNotFound = image_not_found
    mock_client.containers.create.side_effect = [
        image_not_found("gcc:latest"),
        mock_container,
    ]

    sandbox._client = mock_client

    # _get_docker mock'la
    with mock.patch("offsploit.docker_sandbox._get_docker", return_value=mock_docker_module):
        exit_code, stdout, stderr = sandbox._run_container(
            image="gcc:latest",
            command="gcc /tmp/test.c",
            source_code="int main() { return 0; }",
            source_file="/tmp/test.c",
        )

    # İkinci create çağrısını kontrol et
    assert mock_client.containers.create.call_count == 2
    second_call = mock_client.containers.create.call_args_list[1]
    all_kwargs = {**second_call.kwargs}
    assert all_kwargs.get("cap_drop") == ["ALL"], "İkinci create çağrısında cap_drop eksik!"
    assert all_kwargs.get("network_mode") == "none"
    assert all_kwargs.get("security_opt") == ["no-new-privileges:true"]


# ─────────────────────────────────────────────
# Test 5: compile_in_sandbox güvenlik propagation
# ─────────────────────────────────────────────

def test_compile_in_sandbox_uses_secure_kwargs():
    """compile_in_sandbox metodu _create_container_kwargs'ı kullanmalı."""
    from offsploit.docker_sandbox import DockerSandbox

    sandbox = DockerSandbox()

    # _run_container'ı mock'la ve çağrıldığını doğrula
    with mock.patch.object(sandbox, "_run_container", return_value=(0, "OK", "")) as mock_run:
        result = sandbox.compile_in_sandbox("int main() {}", "c")

        mock_run.assert_called_once()
        assert result.success is True


# ─────────────────────────────────────────────
# Test 6: Güvenlik sabitleri değiştirilemiyor (class-level koruma)
# ─────────────────────────────────────────────

def test_security_constants_are_class_level():
    """Güvenlik sabitleri sınıf seviyesinde tanımlı ve her instance'da aynı."""
    from offsploit.docker_sandbox import DockerSandbox

    s1 = DockerSandbox(memory_limit="128m")
    s2 = DockerSandbox(memory_limit="512m")

    # Güvenlik sabitleri farklı instance'larda aynı
    assert s1._SECURITY_CAP_DROP is s2._SECURITY_CAP_DROP
    assert s1._SECURITY_NETWORK_MODE == s2._SECURITY_NETWORK_MODE
    assert s1._SECURITY_OPT is s2._SECURITY_OPT
    assert s1._SECURITY_PIDS_LIMIT == s2._SECURITY_PIDS_LIMIT

    # Bellek limitleri farklı (bu güvenlik sabiti değil)
    assert s1.memory_limit != s2.memory_limit


# ─────────────────────────────────────────────
# Test 7: Kwargs her zaman network_mode=none içerir
# ─────────────────────────────────────────────

def test_kwargs_always_contains_network_none():
    """Farklı diller için oluşturulan kwargs hep network_mode=none içermeli."""
    from offsploit.docker_sandbox import DockerSandbox

    sandbox = DockerSandbox()

    for cmd in ["gcc test.c", "python3 test.py", "g++ test.cpp"]:
        kwargs = sandbox._create_container_kwargs("test:latest", cmd)
        assert kwargs["network_mode"] == "none", f"network_mode 'none' değil: {cmd}"
        assert kwargs["cap_drop"] == ["ALL"], f"cap_drop ALL değil: {cmd}"
