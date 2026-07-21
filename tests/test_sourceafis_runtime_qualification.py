from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from tools import qualify_sourceafis_runtime_v1 as qualification


def _java_output(home: Path, *, version: str = "17.0.18", runtime: str = "17.0.18+8-LTS",
                 vendor: str = "Azul Systems, Inc.", architecture: str = "amd64",
                 distribution: str = "Zulu17.64+17-CA") -> str:
    return f"""Property settings:
    java.home = {home}
    java.runtime.version = {runtime}
    java.vendor = {vendor}
    os.arch = {architecture}
openjdk version "{version}" 2026-01-20 LTS
OpenJDK Runtime Environment {distribution} (build {runtime})
"""


def _maven_output(home: Path, *, maven: str = "3.9.16", java: str = "17.0.18",
                  vendor: str = "Azul Systems, Inc.") -> str:
    return f"""Apache Maven {maven} (NON_CANONICAL)
Maven home: ignored
Java version: {java}, vendor: {vendor}, runtime: {home}
Default locale: en_US, platform encoding: UTF-8
"""


def _environment(home: Path, **overrides):
    java_arguments = overrides.pop("java_arguments", {})
    maven_arguments = overrides.pop("maven_arguments", {})
    javac = overrides.pop("javac", "17.0.18")
    assert not overrides
    return qualification.validate_environment_outputs(
        _java_output(home, **java_arguments),
        f"javac {javac}\n",
        _maven_output(home, **maven_arguments),
        home,
    )


def _pom(path: Path, *, release: str = "11", sourceafis: str = "3.18.1") -> Path:
    path.write_text(
        f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <properties>
    <maven.compiler.release>{release}</maven.compiler.release>
    <sourceafis.version>{sourceafis}</sourceafis.version>
  </properties>
</project>
""",
        encoding="utf-8",
    )
    return path


def _runs(*, new: bool) -> list[dict[str, object]]:
    templates = {key: hashlib.sha256(key.encode()).hexdigest() for key in qualification.IMAGE_KEYS}
    formats = {key: "sourceafis" for key in qualification.IMAGE_KEYS}
    versions = {key: "3.18.1" for key in qualification.IMAGE_KEYS}
    scores = {key: float(index + 1) for index, key in enumerate(qualification.COMPARISONS)}
    removed = {"/extract-template-raw": 404, "/extract-final-minutiae": 404} if new else {}
    return [
        {
            "repetition": repetition,
            "template_sha256": copy.deepcopy(templates),
            "template_format": copy.deepcopy(formats),
            "template_version": copy.deepcopy(versions),
            "raw_scores": copy.deepcopy(scores),
            "finite_scores": True,
            "removed_route_status": copy.deepcopy(removed),
        }
        for repetition in range(1, 4)
    ]


def _valid_package(root: Path) -> Path:
    root.mkdir()
    artifacts = {
        "README.md": "qualification package\n",
        "QUALIFICATION_REPORT.md": "PASS\n",
        "qualification_manifest.json": json.dumps({"cohort_member": False}),
        "qualification_results.json": json.dumps({"status": {"status": "PASS"}}),
        "qualification_environment.json": json.dumps({"java_version": "17.0.18"}),
    }
    for name, text in artifacts.items():
        (root / name).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    locked = {
        name: {"sha256": qualification.file_sha256(root / name), "size_bytes": (root / name).stat().st_size}
        for name in artifacts
    }
    (root / "qualification_lock.json").write_text(
        json.dumps({"status": "PASS", "package_files": locked}) + "\n", encoding="utf-8",
    )
    sums = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        sums.append(f"{qualification.file_sha256(path)}  {path.name}")
    (root / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    qualification.validate_package(root)
    return root


def test_accepts_canonical_zulu_17_0_18_environment(tmp_path):
    environment = _environment(tmp_path / "jvm")
    assert environment.java_distribution == "Zulu OpenJDK"
    assert environment.java_version == "17.0.18"
    assert environment.maven_version == "3.9.16"
    assert environment.compiler_release == 11


def test_maven_parser_preserves_vendor_name_containing_comma(tmp_path):
    parsed = qualification.parse_maven_version(_maven_output(tmp_path / "jvm"))
    assert parsed["java_vendor"] == "Azul Systems, Inc."
    assert parsed["java_runtime"] == str(tmp_path / "jvm")


@pytest.mark.parametrize("version", ["17.0.17", "17.0.19", "21.0.8", "25.0.1"])
def test_rejects_noncanonical_java_versions(tmp_path, version):
    with pytest.raises(qualification.QualificationError, match="exactly 17.0.18"):
        _environment(tmp_path / "jvm", java_arguments={"version": version})


def test_rejects_noncanonical_java_runtime_build(tmp_path):
    with pytest.raises(qualification.QualificationError, match=r"17.0.18\+8-LTS"):
        _environment(tmp_path / "jvm", java_arguments={"runtime": "17.0.18+9-LTS"})


def test_rejects_non_azul_vendor(tmp_path):
    with pytest.raises(qualification.QualificationError, match="Azul Zulu"):
        _environment(tmp_path / "jvm", java_arguments={"vendor": "Eclipse Adoptium"})


def test_rejects_non_zulu_distribution(tmp_path):
    with pytest.raises(qualification.QualificationError, match="Azul Zulu"):
        _environment(tmp_path / "jvm", java_arguments={"distribution": "OpenJDK"})


def test_rejects_non_x64_java(tmp_path):
    with pytest.raises(qualification.QualificationError, match="amd64/x64"):
        _environment(tmp_path / "jvm", java_arguments={"architecture": "aarch64"})


def test_rejects_noncanonical_javac(tmp_path):
    with pytest.raises(qualification.QualificationError, match="javac"):
        _environment(tmp_path / "jvm", javac="11.0.29")


def test_rejects_noncanonical_maven(tmp_path):
    with pytest.raises(qualification.QualificationError, match="Maven"):
        _environment(tmp_path / "jvm", maven_arguments={"maven": "3.9.15"})


def test_rejects_maven_using_other_java_version(tmp_path):
    with pytest.raises(qualification.QualificationError, match="Maven is not using"):
        _environment(tmp_path / "jvm", maven_arguments={"java": "21.0.8"})


def test_rejects_maven_using_other_vendor(tmp_path):
    with pytest.raises(qualification.QualificationError, match="Maven is not using"):
        _environment(tmp_path / "jvm", maven_arguments={"vendor": "Oracle Corporation"})


def test_rejects_maven_using_other_java_home(tmp_path):
    home = tmp_path / "jvm"
    with pytest.raises(qualification.QualificationError, match="Maven Java home"):
        qualification.validate_environment_outputs(
            _java_output(home), "javac 17.0.18\n", _maven_output(tmp_path / "other"), home,
        )


def test_rejects_launcher_reporting_other_java_home(tmp_path):
    home = tmp_path / "jvm"
    with pytest.raises(qualification.QualificationError, match="launcher home"):
        qualification.validate_environment_outputs(
            _java_output(tmp_path / "other"), "javac 17.0.18\n", _maven_output(home), home,
        )


def test_accepts_compiler_release_11_and_sourceafis_3_18_1(tmp_path):
    qualification.validate_pom(_pom(tmp_path / "pom.xml"))


def test_rejects_compiler_release_17(tmp_path):
    with pytest.raises(qualification.QualificationError, match="release is not Java 11"):
        qualification.validate_pom(_pom(tmp_path / "pom.xml", release="17"))


def test_rejects_other_sourceafis_version(tmp_path):
    with pytest.raises(qualification.QualificationError, match="SourceAFIS version"):
        qualification.validate_pom(_pom(tmp_path / "pom.xml", sourceafis="3.19.0"))


def test_subprocess_environment_is_explicit_and_nonpersistent(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "original-path")
    monkeypatch.delenv("JAVA_HOME", raising=False)
    java = tmp_path / "Library" / "bin" / "java.exe"
    home = tmp_path / "Library" / "lib" / "jvm"
    environment = qualification.qualification_subprocess_env(home, java)
    assert environment["JAVA_HOME"] == str(home)
    assert environment["PATH"].split(os.pathsep)[0] == str(java.parent)
    assert os.environ.get("JAVA_HOME") is None
    assert os.environ["PATH"] == "original-path"


def test_canonical_runtime_layout_accepts_required_conda_paths(tmp_path):
    environment = tmp_path / "fingerprint-recognition-research"
    library = environment / "Library"
    home = library / "lib" / "jvm"
    for path in (library / "bin" / "java.exe", library / "bin" / "javac.exe",
                 library / "bin" / "mvn.cmd", home / "bin" / "java.exe"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"launcher")
    qualification.canonical_runtime_paths(
        library / "bin" / "java.exe", library / "bin" / "javac.exe",
        library / "bin" / "mvn.cmd", home,
    )


def test_canonical_runtime_layout_rejects_other_java_executable(tmp_path):
    environment = tmp_path / "fingerprint-recognition-research"
    home = environment / "Library" / "lib" / "jvm"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "java.exe").write_bytes(b"launcher")
    with pytest.raises(qualification.QualificationError, match="canonical java path"):
        qualification.canonical_runtime_paths(
            tmp_path / "other" / "java.exe", environment / "Library" / "bin" / "javac.exe",
            environment / "Library" / "bin" / "mvn.cmd", home,
        )


def test_old_and_new_launch_commands_use_identical_java_executable(tmp_path):
    java = tmp_path / "canonical" / "java.exe"
    old = qualification.SidecarSpec("old", tmp_path / "old.jar", "old-contract", "0.4.0", "environment")
    new = qualification.SidecarSpec("new", tmp_path / "new.jar", "new-contract", "1.0.0", "arguments")
    old_command = qualification.sidecar_launch_command(old, java, 1234)
    new_command = qualification.sidecar_launch_command(new, java, 5678)
    assert old_command[0] == new_command[0] == str(java)
    assert "--host" not in old_command
    assert new_command[-4:] == ["--host", "127.0.0.1", "--port", "5678"]


def test_old_and_new_build_commands_use_identical_maven_executable(tmp_path):
    maven = tmp_path / "canonical" / "mvn.cmd"
    old = qualification.maven_build_command(maven, tmp_path / "old" / "pom.xml")
    new = qualification.maven_build_command(maven, tmp_path / "new" / "pom.xml")
    assert old[0] == new[0] == str(maven)
    assert old[1:3] == new[1:3] == ["-V", "-f"]


def test_removed_route_status_does_not_require_json_response(monkeypatch):
    class Response:
        status = 404

        def read(self):
            return b"<h1>404 Not Found</h1>"

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(qualification.http.client, "HTTPConnection", Connection)
    assert qualification._http_status(1234, "POST", "/removed", {}) == 404


def test_environment_artifact_does_not_store_absolute_conda_path(tmp_path):
    artifact = _environment(tmp_path / "jvm").artifact()
    serialized = json.dumps(artifact)
    assert "C:\\Users\\" not in serialized
    assert "fingerprint-recognition-research" in serialized
    qualification._assert_safe_json(artifact)


def test_safe_artifact_validation_rejects_absolute_windows_path():
    with pytest.raises(qualification.QualificationError, match="absolute local path"):
        qualification._assert_safe_json({"java": r"C:\Users\researcher\java.exe"})


@pytest.mark.parametrize("artifact", [
    {"template_base64": "abc"},
    {"image_bytes": "abc"},
    {"threshold_used": True},
    {"decision_logic": "accept-if-high"},
])
def test_safe_artifact_validation_rejects_sensitive_or_policy_fields(artifact):
    with pytest.raises(qualification.QualificationError):
        qualification._assert_safe_json(artifact)


def test_metadata_selection_excludes_every_prohibited_subject():
    def row(subject):
        return {
            "subject_id": subject,
            "has_all_10_fingers_b": "true", "has_all_10_fingers_c": "true", "has_all_10_in_both": "true",
            "plain_count_b": "10", "roll_count_b": "10", "pair_count_b": "10",
            "plain_count_c": "10", "roll_count_c": "10", "pair_count_c": "10",
            "eligible_for_core_selection": "true",
        }
    rows = [row(subject) for subject in ("00000001", "00000002", "00000003", "00001585", "00000004")]
    selected = qualification.select_subject(rows, {"00000001"}, {"00000002"}, {"00000003"})
    assert selected == "00000004"


def test_metadata_selection_has_no_fallback():
    with pytest.raises(qualification.QualificationError) as error:
        qualification.select_subject([], set(), set(), set())
    assert error.value.status == "BLOCKED"


def test_canonical_pair_requires_finger_one_and_exactly_one_row():
    row = {
        "subject_id": "00000004", "canonical_finger": "1", "dataset_release": "SD300B",
        "pair_status": "valid",
    }
    assert qualification.find_canonical_pair([row], "00000004", "SD300B") is row
    with pytest.raises(qualification.QualificationError, match="missing or duplicated"):
        qualification.find_canonical_pair([{**row, "canonical_finger": "2"}], "00000004", "SD300B")
    with pytest.raises(qualification.QualificationError, match="missing or duplicated"):
        qualification.find_canonical_pair([row, copy.deepcopy(row)], "00000004", "SD300B")


def test_fixture_hash_mismatch_fails_before_matcher(tmp_path):
    image = tmp_path / "image.bin"
    image.write_bytes(b"ordinary non-fingerprint bytes")
    with pytest.raises(qualification.QualificationError, match="fixture image hash mismatch"):
        qualification.verify_image_hash(image, "0" * 64, "sd300b/image.bin")


def test_manual_and_blocked_subject_parsers_cover_all_identifiers():
    manual = qualification.manual_review_subjects([{"logical_record_key": "00000002|sd300b|1"}])
    blocked = qualification.blocked_subjects([
        {"selection_blocked": "true", "subject_id_a": "00000003", "subject_id_b": "00000004"},
    ])
    assert manual == {"00000002"}
    assert blocked == {"00000003", "00000004"}


@pytest.mark.parametrize("change", ["template", "score", "identity", "removed"])
def test_repetition_validation_rejects_any_determinism_or_parity_failure(change):
    old, new = _runs(new=False), _runs(new=True)
    if change == "template":
        old[1]["template_sha256"][qualification.IMAGE_KEYS[0]] = "0" * 64
    elif change == "score":
        new[2]["raw_scores"][qualification.COMPARISONS[0]] = 999.0
    elif change == "identity":
        new[0]["template_version"][qualification.IMAGE_KEYS[0]] = "other"
    else:
        new[1]["removed_route_status"].pop("/extract-template-raw")
    with pytest.raises(qualification.QualificationError):
        qualification.validate_repetitions(old, new)


def test_repetition_validation_accepts_three_exact_old_new_runs():
    checks = qualification.validate_repetitions(_runs(new=False), _runs(new=True))
    assert checks == {
        "old_internal_determinism": True,
        "new_internal_determinism": True,
        "template_parity": True,
        "score_parity": True,
        "removed_routes_absent": True,
    }


def test_repetition_validation_rejects_nonfinite_score_flag():
    old, new = _runs(new=False), _runs(new=True)
    old[0]["finite_scores"] = False
    with pytest.raises(qualification.QualificationError, match="non-finite"):
        qualification.validate_repetitions(old, new)


def test_manifest_has_exact_successful_path_scope(tmp_path):
    images = {
        key: qualification.QualifiedImage(key, tmp_path / key, f"sd300b/{key}", "a" * 64, 1000)
        for key in qualification.IMAGE_KEYS
    }
    fixture = qualification.Fixture("00000004", 1, images)
    manifest = qualification.qualification_manifest(fixture)
    assert manifest["comparisons"] == list(qualification.COMPARISONS)
    assert manifest["selection_policy"]["fallback_allowed"] is False
    assert manifest["cohort_member"] is False
    assert manifest["threshold_input"] is False


def test_dataset_path_must_remain_below_release_root(tmp_path):
    dataset = tmp_path / "dataset"
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"data")
    with pytest.raises(qualification.QualificationError, match="escapes dataset root"):
        qualification._safe_dataset_path(dataset, str(outside), "sd300b")


def test_temporary_workspace_is_removed_on_failure(tmp_path):
    with pytest.raises(RuntimeError):
        with qualification.temporary_workspace(tmp_path) as workspace:
            (workspace / "temporary.jar").write_bytes(b"temporary")
            raise RuntimeError("simulated failure")
    assert not (tmp_path / ".qualification-tmp").exists()


def test_protocol_tree_hash_detects_any_modification(tmp_path):
    protocol = tmp_path / "protocol"
    protocol.mkdir()
    file = protocol / "manifest.csv"
    file.write_text("before\n", encoding="utf-8")
    before = qualification.tree_sha256(protocol)
    file.write_text("after\n", encoding="utf-8")
    assert qualification.tree_sha256(protocol) != before


def test_parser_exposes_no_subject_finger_threshold_or_decision_override():
    options = {option for action in qualification.parser()._actions for option in action.option_strings}
    assert not options.intersection({"--subject", "--finger", "--threshold", "--decision"})


def test_qualification_tool_never_invokes_research_manifest_runner():
    tool = Path(qualification.__file__).read_text(encoding="utf-8")
    assert "run-sourceafis-manifest" not in tool


def test_publish_candidate_replaces_existing_package_only_after_validation(tmp_path):
    destination = tmp_path / "qualification"
    destination.mkdir()
    (destination / "blocked.txt").write_text("BLOCKED", encoding="utf-8")
    candidate = _valid_package(tmp_path / "candidate")
    qualification.publish_candidate(candidate, destination, replace=True)
    qualification.validate_package(destination)
    assert not candidate.exists()
    assert not (destination / "blocked.txt").exists()


def test_publish_candidate_rolls_back_existing_package_on_post_move_failure(tmp_path, monkeypatch):
    destination = tmp_path / "qualification"
    destination.mkdir()
    marker = destination / "blocked.txt"
    marker.write_text("BLOCKED", encoding="utf-8")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "payload").write_text("new", encoding="utf-8")
    calls = 0

    def validate(_path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise qualification.QualificationError("FAIL", "simulated post-move failure")

    monkeypatch.setattr(qualification, "validate_package", validate)
    with pytest.raises(qualification.QualificationError):
        qualification.publish_candidate(candidate, destination, replace=True)
    assert marker.read_text(encoding="utf-8") == "BLOCKED"


def test_publish_candidate_removes_new_destination_on_post_move_failure(tmp_path, monkeypatch):
    destination = tmp_path / "qualification"
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "payload").write_text("new", encoding="utf-8")
    calls = 0

    def validate(_path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise qualification.QualificationError("FAIL", "simulated post-move failure")

    monkeypatch.setattr(qualification, "validate_package", validate)
    with pytest.raises(qualification.QualificationError):
        qualification.publish_candidate(candidate, destination, replace=True)
    assert not destination.exists()


def test_committed_qualification_package_is_locked_and_dataset_independent():
    repository = Path(__file__).resolve().parents[1]
    package = repository / "qualification" / qualification.QUALIFICATION_ID
    qualification.validate_package(package)
    qualification.validate_repository_bindings(package, repository)
