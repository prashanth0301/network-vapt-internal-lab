import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.artifact import Artifact
from app.services.artifact_manager import ArtifactManager, artifact_manager


class TestArtifactManagerInit:
    def test_default_base_dir(self):
        assert artifact_manager.base_dir is not None
        assert artifact_manager.base_dir.name == "artifacts"

    def test_custom_base_dir(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        assert manager.base_dir == tmp_path


class TestDirectoryCreation:
    def test_create_stage_directory(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        assessment_id = str(uuid.uuid4())
        stage_dir = manager.create_stage_directory(assessment_id, "host_discovery")
        assert stage_dir.exists()
        assert stage_dir.is_dir()
        assert stage_dir.name == "host_discovery"
        assert assessment_id[:8] in str(stage_dir)

    def test_create_multiple_stages(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        assessment_id = str(uuid.uuid4())
        d1 = manager.create_stage_directory(assessment_id, "host_discovery")
        d2 = manager.create_stage_directory(assessment_id, "port_scan")
        assert d1.exists()
        assert d2.exists()
        assert d1.parent == d2.parent


class TestSaveArtifacts:
    @pytest.fixture
    def manager(self, tmp_path):
        return ArtifactManager(base_dir=tmp_path)

    @pytest.fixture
    def stage_dir(self, manager):
        return manager.create_stage_directory(str(uuid.uuid4()), "test_stage")

    def test_save_command(self, manager, stage_dir):
        manager.save_command(stage_dir, "nmap -sn 192.168.56.0/24")
        cmd_file = stage_dir / "command.txt"
        assert cmd_file.exists()
        assert cmd_file.read_text() == "nmap -sn 192.168.56.0/24"

    def test_save_metadata(self, manager, stage_dir):
        metadata = {"key": "value", "number": 42}
        manager.save_metadata(stage_dir, metadata)
        meta_file = stage_dir / "metadata.json"
        assert meta_file.exists()
        loaded = json.loads(meta_file.read_text())
        assert loaded["key"] == "value"
        assert loaded["number"] == 42

    def test_save_xml(self, manager, stage_dir):
        xml_content = "<nmaprun><host></host></nmaprun>"
        manager.save_xml(stage_dir, xml_content)
        xml_file = stage_dir / "output.xml"
        assert xml_file.exists()
        assert xml_file.read_text() == xml_content

    def test_save_json_default_name(self, manager, stage_dir):
        data = {"ports": [22, 80], "count": 2}
        manager.save_json(stage_dir, data)
        json_file = stage_dir / "output.json"
        assert json_file.exists()
        loaded = json.loads(json_file.read_text())
        assert loaded["count"] == 2

    def test_save_json_custom_name(self, manager, stage_dir):
        data = {"host": "192.168.56.20", "ports": []}
        manager.save_json(stage_dir, data, filename="results.json")
        json_file = stage_dir / "results.json"
        assert json_file.exists()
        loaded = json.loads(json_file.read_text())
        assert loaded["host"] == "192.168.56.20"

    def test_save_text(self, manager, stage_dir):
        content = "stdout line 1\nstdout line 2"
        manager.save_text(stage_dir, "stdout.txt", content)
        txt_file = stage_dir / "stdout.txt"
        assert txt_file.exists()
        assert txt_file.read_text() == content

    def test_save_error(self, manager, stage_dir):
        error = "Connection refused"
        manager.save_error(stage_dir, error)
        err_file = stage_dir / "stderr.txt"
        assert err_file.exists()
        assert err_file.read_text() == error


class TestLoadArtifacts:
    @pytest.fixture
    def manager(self, tmp_path):
        return ArtifactManager(base_dir=tmp_path)

    @pytest.fixture
    def stage_dir(self, manager):
        d = manager.create_stage_directory(str(uuid.uuid4()), "test_load")
        (d / "command.txt").write_text("nmap -sn target")
        (d / "metadata.json").write_text('{"key": "value"}')
        (d / "output.xml").write_text("<xml></xml>")
        return d

    def test_load_existing_file(self, manager, stage_dir):
        content = manager.load_artifact(stage_dir, "command.txt")
        assert content == "nmap -sn target"

    def test_load_nonexistent_file(self, manager, stage_dir):
        content = manager.load_artifact(stage_dir, "nonexistent.txt")
        assert content is None

    def test_load_existing_json(self, manager, stage_dir):
        data = manager.load_json_artifact(stage_dir, "metadata.json")
        assert data == {"key": "value"}

    def test_load_nonexistent_json(self, manager, stage_dir):
        data = manager.load_json_artifact(stage_dir, "missing.json")
        assert data is None

    def test_load_invalid_json(self, manager, stage_dir):
        (stage_dir / "bad.json").write_text("not json")
        data = manager.load_json_artifact(stage_dir, "bad.json")
        assert data is None


class TestListArtifacts:
    @pytest.fixture
    def manager(self, tmp_path):
        return ArtifactManager(base_dir=tmp_path)

    @pytest.fixture
    def stage_dir(self, manager):
        d = manager.create_stage_directory(str(uuid.uuid4()), "test_list")
        (d / "command.txt").write_text("cmd")
        (d / "output.json").write_text("{}")
        return d

    def test_list_returns_files(self, manager, stage_dir):
        files = manager.list_artifacts(stage_dir)
        assert len(files) == 2
        filenames = [f["filename"] for f in files]
        assert "command.txt" in filenames
        assert "output.json" in filenames

    def test_list_all_have_keys(self, manager, stage_dir):
        files = manager.list_artifacts(stage_dir)
        for f in files:
            assert "filename" in f
            assert "size" in f
            assert "modified_at" in f

    def test_list_nonexistent_dir(self, manager):
        files = manager.list_artifacts(Path("/nonexistent"))
        assert files == []

    def test_list_empty_dir(self, manager):
        d = manager.create_stage_directory(str(uuid.uuid4()), "empty_test")
        files = manager.list_artifacts(d)
        assert files == []


class TestDeleteArtifacts:
    @pytest.fixture
    def manager(self, tmp_path):
        return ArtifactManager(base_dir=tmp_path)

    def test_delete_existing(self, manager):
        d = manager.create_stage_directory(str(uuid.uuid4()), "to_delete")
        (d / "file.txt").write_text("content")
        assert d.exists()
        result = manager.delete_artifact_files(d)
        assert result is True
        assert not d.exists()

    def test_delete_nonexistent(self, manager):
        result = manager.delete_artifact_files(Path("/nonexistent"))
        assert result is False

    def test_delete_empty_dir(self, manager):
        d = manager.create_stage_directory(str(uuid.uuid4()), "empty_del")
        assert d.exists()
        result = manager.delete_artifact_files(d)
        assert result is True
        assert not d.exists()


class TestStoreMetadata:
    @pytest.mark.asyncio
    async def test_store_metadata(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "meta_store")
        (d / "file.txt").write_text("content")

        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        start_time = datetime.now(timezone.utc)
        end_time = datetime.now(timezone.utc)

        result = await manager.store_metadata(
            session=mock_session,
            assessment_id=str(uuid.uuid4()),
            stage_name="test_stage",
            artifact_dir=d,
            status="completed",
            scanner_name="nmap",
            command="nmap -sn target",
            parameters={"key": "value"},
            target="192.168.56.0/24",
            start_time=start_time,
            end_time=end_time,
            duration=10.5,
            output_type="xml",
        )
        assert result is not None
        assert result.stage_name == "test_stage"
        assert result.status == "completed"
        assert result.duration == 10.5
        assert result.output_type == "xml"
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_metadata_non_uuid_assessment(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "meta_non_uuid")
        (d / "f.txt").write_text("x")

        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        result = await manager.store_metadata(
            session=mock_session,
            assessment_id="not-a-uuid",
            stage_name="test",
            artifact_dir=d,
            status="completed",
        )
        assert result is not None
        assert result.stage_name == "test"
        mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_metadata_generates_hash(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "meta_hash")
        (d / "data.txt").write_text("content for hash")

        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        result = await manager.store_metadata(
            session=mock_session,
            assessment_id=str(uuid.uuid4()),
            stage_name="hash_test",
            artifact_dir=d,
            status="completed",
        )
        assert result.hash is not None
        assert len(result.hash) == 64


class TestGetArtifacts:
    @pytest.mark.asyncio
    async def test_get_artifact_by_id_found(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "get_test")
        (d / "f.txt").write_text("x")

        artifact_id = uuid.uuid4()
        mock_artifact = MagicMock(spec=Artifact)
        mock_artifact.id = artifact_id

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_artifact

        result = await manager.get_artifact_by_id(mock_session, str(artifact_id))
        assert result is not None
        assert result.id == artifact_id

    @pytest.mark.asyncio
    async def test_get_artifact_by_id_not_found(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        result = await manager.get_artifact_by_id(mock_session, str(uuid.uuid4()))
        assert result is None

    @pytest.mark.asyncio
    async def test_get_artifacts_pagination(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()

        count_result = MagicMock()
        count_result.fetchall = MagicMock(return_value=[MagicMock() for _ in range(20)])

        list_result = MagicMock()
        list_result.scalars.return_value.all.return_value = [MagicMock() for _ in range(5)]

        mock_session.execute.side_effect = [count_result, list_result]

        artifacts, total = await manager.get_artifacts(
            mock_session, page=1, per_page=10
        )
        assert total == 20
        assert len(artifacts) == 5

    @pytest.mark.asyncio
    async def test_get_artifacts_with_assessment_filter(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        assessment_id = str(uuid.uuid4())

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()

        count_result = MagicMock()
        count_result.fetchall = MagicMock(return_value=[])
        mock_session.execute.return_value = count_result

        artifacts, total = await manager.get_artifacts(
            mock_session, assessment_id=assessment_id, page=1, per_page=20
        )
        assert total == 0
        assert artifacts == []


class TestComputeHash:
    def test_hash_changes_with_content(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "hash_test")

        (d / "a.txt").write_text("hello")
        hash1 = manager._compute_hash(d)

        (d / "b.txt").write_text("world")
        hash2 = manager._compute_hash(d)

        assert hash1 is not None
        assert hash2 is not None
        assert hash1 != hash2

    def test_hash_deterministic(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "hash_det")

        (d / "f.txt").write_text("fixed content")
        hash1 = manager._compute_hash(d)
        hash2 = manager._compute_hash(d)
        assert hash1 == hash2

    def test_hash_empty_dir(self, tmp_path):
        manager = ArtifactManager(base_dir=tmp_path)
        d = manager.create_stage_directory(str(uuid.uuid4()), "hash_empty")
        h = manager._compute_hash(d)
        assert h is None
