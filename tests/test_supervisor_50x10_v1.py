"""Acceptance tests for the frozen supervisor_50x10_v1 protocol package."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPOSITORY_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from build_supervisor_50x10_v1 import build_package  # noqa: E402
from validate_supervisor_50x10_v1 import (  # noqa: E402
    COMPARISON_KINDS,
    MANIFEST_COLUMNS,
    MANIFEST_FILENAMES,
    PROTOCOL_ID,
    RELEASES,
    read_csv,
    sha256_file,
    validate_protocol,
)


CURATION_ROOT = Path(r"C:\fingerprint-datasets\NIST\_curation\stage0_v1")
DATASET_ROOT = Path(r"C:\fingerprint-datasets\NIST")
PACKAGE_ROOT = REPOSITORY_ROOT / "protocols" / PROTOCOL_ID
TEST_ROOT = REPOSITORY_ROOT / "tests" / "_tmp_supervisor_50x10_v1"


def tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def rewrite_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class SupervisorProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if TEST_ROOT.exists():
            shutil.rmtree(TEST_ROOT)
        TEST_ROOT.mkdir(parents=True)
        cls.build_a = TEST_ROOT / "build_a"
        cls.build_b = TEST_ROOT / "build_b"
        build_package(CURATION_ROOT, DATASET_ROOT, cls.build_a)
        build_package(CURATION_ROOT, DATASET_ROOT, cls.build_b)
        cls.curation_fixture = TEST_ROOT / "curation_fixture"
        cls._copy_minimal_curation_fixture()

    @classmethod
    def tearDownClass(cls) -> None:
        if TEST_ROOT.exists():
            shutil.rmtree(TEST_ROOT)

    @classmethod
    def _copy_minimal_curation_fixture(cls) -> None:
        old_lock = json.loads((CURATION_ROOT / "outputs" / "manifest_lock.json").read_text(encoding="utf-8"))
        (cls.curation_fixture / "outputs").mkdir(parents=True)
        (cls.curation_fixture / "scripts").mkdir()
        (cls.curation_fixture / "config").mkdir()
        for name in old_lock["artifact_sha256"]:
            shutil.copyfile(CURATION_ROOT / "outputs" / name, cls.curation_fixture / "outputs" / name)
        shutil.copyfile(
            CURATION_ROOT / "outputs" / "MANIFEST_SHA256SUMS.txt",
            cls.curation_fixture / "outputs" / "MANIFEST_SHA256SUMS.txt",
        )
        for name in old_lock["script_sha256"]:
            shutil.copyfile(CURATION_ROOT / "scripts" / name, cls.curation_fixture / "scripts" / name)
        shutil.copyfile(
            CURATION_ROOT / "config" / "stage0_config.yaml",
            cls.curation_fixture / "config" / "stage0_config.yaml",
        )
        shutil.copyfile(
            CURATION_ROOT / "config" / "manual_review_decisions.csv",
            cls.curation_fixture / "config" / "manual_review_decisions.csv",
        )

    def _copy_build(self, name: str) -> Path:
        target = TEST_ROOT / name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(self.build_a, target)
        return target

    def _validate(self, root: Path):
        return validate_protocol(root, CURATION_ROOT, DATASET_ROOT, repository_root=REPOSITORY_ROOT)

    def test_01_two_builds_are_byte_identical(self) -> None:
        self.assertEqual(tree_bytes(self.build_a), tree_bytes(self.build_b))

    def test_02_every_manifest_has_500_rows(self) -> None:
        counts = []
        for release in RELEASES:
            for kind in COMPARISON_KINDS:
                header, rows = read_csv(self.build_a / release / MANIFEST_FILENAMES[kind])
                self.assertEqual(header, MANIFEST_COLUMNS)
                counts.append(len(rows))
        self.assertEqual(counts, [500] * 8)

    def test_03_each_release_is_50_by_10(self) -> None:
        for release in RELEASES:
            _, rows = read_csv(self.build_a / release / "plain_roll_genuine.csv")
            subject_fingers: dict[str, set[int]] = {}
            for row in rows:
                subject_fingers.setdefault(row["subject_id_a"], set()).add(int(row["canonical_finger"]))
            self.assertEqual(len(subject_fingers), 50)
            self.assertTrue(all(fingers == set(range(1, 11)) for fingers in subject_fingers.values()))

    def test_04_self_pairs_are_identity_pairs(self) -> None:
        for release in RELEASES:
            for kind, capture in (("plain_self", "PLAIN"), ("roll_self", "ROLL")):
                _, rows = read_csv(self.build_a / release / MANIFEST_FILENAMES[kind])
                for row in rows:
                    self.assertEqual(row["subject_id_a"], row["subject_id_b"])
                    self.assertEqual(row["relative_path_a"], row["relative_path_b"])
                    self.assertEqual(row["sha256_a"], row["sha256_b"])
                    self.assertEqual((row["capture_type_a"], row["capture_type_b"]), (capture, capture))

    def test_05_genuine_pairs_preserve_identity(self) -> None:
        for release in RELEASES:
            _, rows = read_csv(self.build_a / release / "plain_roll_genuine.csv")
            for row in rows:
                self.assertEqual(row["subject_id_a"], row["subject_id_b"])
                self.assertEqual(row["subject_index_a"], row["subject_index_b"])
                self.assertEqual((row["capture_type_a"], row["capture_type_b"]), ("PLAIN", "ROLL"))

    def test_06_impostor_pairs_use_cyclic_next_subject(self) -> None:
        selected = [
            row["subject_id"]
            for row in read_csv(self.build_a / "provenance" / "selected_50_subjects.csv")[1]
        ]
        for release in RELEASES:
            _, rows = read_csv(self.build_a / release / "plain_roll_next_subject.csv")
            for position, row in enumerate(rows):
                index_a = position // 10
                index_b = (index_a + 1) % 50
                self.assertEqual(row["subject_id_a"], selected[index_a])
                self.assertEqual(row["subject_id_b"], selected[index_b])
                self.assertNotEqual(row["subject_id_a"], row["subject_id_b"])

    def test_07_nominal_ppi_is_release_specific(self) -> None:
        for release, ppi in RELEASES.items():
            for kind in COMPARISON_KINDS:
                _, rows = read_csv(self.build_a / release / MANIFEST_FILENAMES[kind])
                self.assertEqual({row["nominal_ppi_a"] for row in rows}, {str(ppi)})
                self.assertEqual({row["nominal_ppi_b"] for row in rows}, {str(ppi)})

    def test_08_paths_are_normalized_and_relative(self) -> None:
        for release in RELEASES:
            for kind in COMPARISON_KINDS:
                _, rows = read_csv(self.build_a / release / MANIFEST_FILENAMES[kind])
                for row in rows:
                    for field in ("relative_path_a", "relative_path_b"):
                        value = row[field]
                        self.assertTrue(value.startswith(release + "/"))
                        self.assertNotIn("\\", value)
                        self.assertNotIn(":", value)
                        self.assertNotIn("..", value.split("/"))

    def test_09_challenge_statuses_are_preserved(self) -> None:
        for release in RELEASES:
            source_name = f"base_500_genuine_{release}.csv"
            _, source = read_csv(CURATION_ROOT / "outputs" / source_name)
            _, plain_self = read_csv(self.build_a / release / "plain_self.csv")
            _, genuine = read_csv(self.build_a / release / "plain_roll_genuine.csv")
            self.assertEqual(
                [row["plain_status"] for row in source],
                [row["image_status_a"] for row in plain_self],
            )
            self.assertEqual(
                [row["pair_status"] for row in source],
                [row["pair_status"] for row in genuine],
            )
            self.assertGreater(sum(row["pair_status"] == "challenge" for row in genuine), 0)

    def test_10_self_rows_trace_to_genuine_source_rows(self) -> None:
        for release in RELEASES:
            _, source_rows = read_csv(CURATION_ROOT / "outputs" / f"base_500_genuine_{release}.csv")
            source = {row["pair_id"]: row for row in source_rows}
            for filename, capture in (("plain_self.csv", "plain"), ("roll_self.csv", "roll")):
                _, rows = read_csv(self.build_a / release / filename)
                for row in rows:
                    parent = source[row["source_pair_id"]]
                    self.assertEqual(row["sha256_a"], parent[f"{capture}_sha256"])
                    self.assertEqual(row["source_frgp_a"], parent[f"{capture}_source_frgp"])

    def test_11_manifest_lock_validates(self) -> None:
        result = self._validate(self.build_a)
        self.assertTrue(result.valid, result.errors)
        self.assertTrue(result.checks["package_lock_valid"])

    def test_12_checksum_index_is_complete_and_sorted(self) -> None:
        sums = (self.build_a / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
        paths = [line.split("  ", 1)[1] for line in sums]
        self.assertEqual(paths, sorted(paths))
        self.assertNotIn("SHA256SUMS.txt", paths)
        for line in sums:
            digest, relative = line.split("  ", 1)
            self.assertEqual(digest, sha256_file(self.build_a.joinpath(*relative.split("/"))))

    def test_13_changed_base_manifest_stops_build(self) -> None:
        source = self.curation_fixture / "outputs" / "base_500_genuine_sd300b.csv"
        original = source.read_bytes()
        try:
            source.write_bytes(original + b"\n")
            with self.assertRaises(ValueError):
                build_package(self.curation_fixture, DATASET_ROOT, TEST_ROOT / "changed_base")
        finally:
            source.write_bytes(original)

    def test_14_subject_order_change_fails_validation(self) -> None:
        root = self._copy_build("bad_subject_order")
        path = root / "sd300b" / "plain_self.csv"
        _, rows = read_csv(path)
        rewrite_csv(path, rows[10:20] + rows[0:10] + rows[20:])
        result = self._validate(root)
        self.assertFalse(result.valid)
        self.assertTrue(any("order mismatch" in error for error in result.errors), result.errors)

    def test_15_metadata_ppi_value_5080_fails_validation(self) -> None:
        root = self._copy_build("bad_ppi")
        path = root / "sd300c" / "plain_self.csv"
        _, rows = read_csv(path)
        rows[0]["nominal_ppi_a"] = "5080"
        rewrite_csv(path, rows)
        result = self._validate(root)
        self.assertFalse(result.valid)
        self.assertTrue(any("PPI" in error for error in result.errors), result.errors)

    def test_16_path_escape_fails_validation(self) -> None:
        root = self._copy_build("bad_path")
        path = root / "sd300b" / "plain_self.csv"
        _, rows = read_csv(path)
        rows[0]["relative_path_a"] = "../outside.png"
        rewrite_csv(path, rows)
        result = self._validate(root)
        self.assertFalse(result.valid)
        self.assertTrue(any("path" in error.lower() for error in result.errors), result.errors)

    def test_17_failed_replace_preserves_existing_package(self) -> None:
        output = TEST_ROOT / "atomic_output"
        build_package(CURATION_ROOT, DATASET_ROOT, output)
        before = tree_bytes(output)
        source = self.curation_fixture / "outputs" / "base_500_impostor_sd300c.csv"
        original = source.read_bytes()
        try:
            source.write_bytes(original + b"\n")
            with self.assertRaises(ValueError):
                build_package(self.curation_fixture, DATASET_ROOT, output, replace=True)
        finally:
            source.write_bytes(original)
        self.assertEqual(before, tree_bytes(output))

    def test_18_existing_package_is_not_overwritten_without_replace(self) -> None:
        before = tree_bytes(self.build_a)
        with self.assertRaises(FileExistsError):
            build_package(CURATION_ROOT, DATASET_ROOT, self.build_a)
        self.assertEqual(before, tree_bytes(self.build_a))

    def test_19_runtime_uses_only_standard_library_and_local_modules(self) -> None:
        allowed = {
            "__future__", "argparse", "csv", "dataclasses", "hashlib", "json", "pathlib",
            "shutil", "sys", "typing", "unittest", "build_supervisor_50x10_v1",
            "validate_supervisor_50x10_v1",
        }
        for path in (
            REPOSITORY_ROOT / "tools" / "build_supervisor_50x10_v1.py",
            REPOSITORY_ROOT / "tools" / "validate_supervisor_50x10_v1.py",
            Path(__file__),
        ):
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("import "):
                    roots = [part.strip().split(".", 1)[0] for part in stripped[7:].split(",")]
                elif stripped.startswith("from "):
                    roots = [stripped.split()[1].split(".", 1)[0]]
                else:
                    continue
                self.assertTrue(set(roots).issubset(allowed), (path.name, roots))

    def test_20_metadata_and_selection_provenance_are_frozen(self) -> None:
        metadata = json.loads((self.build_a / "protocol_metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["protocol_id"], PROTOCOL_ID)
        self.assertFalse(metadata["cohort"]["selection_changed"])
        self.assertFalse(metadata["cohort"]["subject_order_changed"])
        self.assertFalse(metadata["curation_caveats"]["suspected_duplicate_claimed_as_biometrically_proven"])
        self.assertTrue(metadata["curation_caveats"]["manual_review_is_provenance_input"])
        source = CURATION_ROOT / "config" / "manual_review_decisions.csv"
        copied = self.build_a / "provenance" / "manual_review_decisions.csv"
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), hashlib.sha256(copied.read_bytes()).digest())


if __name__ == "__main__":
    unittest.main()
