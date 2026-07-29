import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.artifact import Artifact


class ArtifactManager:
    def __init__(self, base_dir: Optional[Path] = None):
        self._base_dir = base_dir or Path(settings.BASE_DIR).parent / "artifacts"

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def create_stage_directory(
        self, assessment_id: str, stage_name: str
    ) -> Path:
        sanitized_assessment = assessment_id.replace("/", "_").replace("\\", "_")
        sanitized_stage = stage_name.replace("/", "_").replace("\\", "_")
        stage_dir = (
            self._base_dir
            / f"assessment_{sanitized_assessment[:8]}"
            / sanitized_stage
        )
        stage_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "Created artifact directory: {path}",
            path=str(stage_dir),
        )
        return stage_dir

    def save_command(self, artifact_dir: Path, command: str) -> None:
        filepath = artifact_dir / "command.txt"
        filepath.write_text(command, encoding="utf-8")
        logger.debug(
            "Saved command artifact: {path}",
            path=str(filepath),
        )

    def save_metadata(self, artifact_dir: Path, metadata: dict) -> None:
        filepath = artifact_dir / "metadata.json"
        filepath.write_text(
            json.dumps(metadata, indent=2, default=str),
            encoding="utf-8",
        )
        logger.debug(
            "Saved metadata artifact: {path}",
            path=str(filepath),
        )

    def save_xml(self, artifact_dir: Path, content: str) -> None:
        filepath = artifact_dir / "output.xml"
        filepath.write_text(content, encoding="utf-8")
        logger.debug(
            "Saved XML artifact: {path}",
            path=str(filepath),
        )

    def save_json(self, artifact_dir: Path, data: Any, filename: str = "output.json") -> None:
        filepath = artifact_dir / filename
        filepath.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        logger.debug(
            "Saved JSON artifact: {path}",
            path=str(filepath),
        )

    def save_text(self, artifact_dir: Path, filename: str, content: str) -> None:
        sanitized = filename.replace("/", "_").replace("\\", "_")
        filepath = artifact_dir / sanitized
        filepath.write_text(content, encoding="utf-8")
        logger.debug(
            "Saved text artifact: {path}",
            path=str(filepath),
        )

    def save_error(self, artifact_dir: Path, error: str) -> None:
        filepath = artifact_dir / "stderr.txt"
        filepath.write_text(error, encoding="utf-8")
        logger.debug(
            "Saved error artifact: {path}",
            path=str(filepath),
        )

    def load_artifact(self, artifact_dir: Path, filename: str) -> Optional[str]:
        sanitized = filename.replace("/", "_").replace("\\", "_")
        filepath = artifact_dir / sanitized
        if not filepath.exists():
            logger.warning(
                "Artifact file not found: {path}",
                path=str(filepath),
            )
            return None
        content = filepath.read_text(encoding="utf-8")
        logger.debug(
            "Loaded artifact: {path} ({size} bytes)",
            path=str(filepath),
            size=len(content),
        )
        return content

    def load_json_artifact(
        self, artifact_dir: Path, filename: str = "metadata.json"
    ) -> Optional[Any]:
        content = self.load_artifact(artifact_dir, filename)
        if content is None:
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(
                "Failed to parse JSON artifact {path}: {error}",
                path=str(artifact_dir / filename),
                error=str(e),
            )
            return None

    def list_artifacts(self, artifact_dir: Path) -> list[dict]:
        if not artifact_dir.exists():
            return []
        files = []
        for entry in sorted(artifact_dir.iterdir()):
            if entry.is_file():
                files.append(
                    {
                        "filename": entry.name,
                        "size": entry.stat().st_size,
                        "modified_at": datetime.fromtimestamp(
                            entry.stat().st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                )
        return files

    def _compute_hash(self, artifact_dir: Path) -> Optional[str]:
        hasher = hashlib.sha256()
        filenames = sorted(
            f.name for f in artifact_dir.iterdir() if f.is_file()
        )
        if not filenames:
            return None
        for name in filenames:
            content = (artifact_dir / name).read_bytes()
            hasher.update(name.encode("utf-8"))
            hasher.update(content)
        return hasher.hexdigest()

    async def store_metadata(
        self,
        session: AsyncSession,
        assessment_id: str,
        stage_name: str,
        artifact_dir: Path,
        status: str = "completed",
        scanner_name: Optional[str] = None,
        command: Optional[str] = None,
        parameters: Optional[dict] = None,
        scanner_version: Optional[str] = None,
        target: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        duration: Optional[float] = None,
        error_message: Optional[str] = None,
        output_type: Optional[str] = None,
    ) -> Artifact:
        artifact_hash = self._compute_hash(artifact_dir)

        try:
            parsed_assessment_id = uuid.UUID(assessment_id) if assessment_id else uuid.uuid4()
        except (ValueError, AttributeError):
            parsed_assessment_id = uuid.uuid4()

        artifact = Artifact(
            assessment_id=parsed_assessment_id,
            stage_name=stage_name,
            scanner_name=scanner_name,
            command=command,
            parameters=parameters,
            scanner_version=scanner_version,
            target=target,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            status=status,
            error_message=error_message,
            artifact_path=str(artifact_dir.resolve()),
            output_type=output_type,
            hash=artifact_hash,
        )
        session.add(artifact)
        await session.flush()
        logger.info(
            "Stored artifact metadata: assessment={assessment}, stage={stage}, id={id}",
            assessment=assessment_id,
            stage=stage_name,
            id=str(artifact.id),
        )
        return artifact

    async def get_artifact_by_id(
        self, session: AsyncSession, artifact_id: str
    ) -> Optional[Artifact]:
        result = await session.execute(
            select(Artifact).where(Artifact.id == uuid.UUID(artifact_id))
        )
        return result.scalar_one_or_none()

    async def get_artifacts(
        self,
        session: AsyncSession,
        assessment_id: Optional[str] = None,
        stage_name: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[list[Artifact], int]:
        query = select(Artifact)

        if assessment_id:
            query = query.where(
                Artifact.assessment_id == uuid.UUID(assessment_id)
            )
        if stage_name:
            query = query.where(Artifact.stage_name == stage_name)

        count_query = select(Artifact.id).select_from(Artifact)
        if assessment_id:
            count_query = count_query.where(
                Artifact.assessment_id == uuid.UUID(assessment_id)
            )
        if stage_name:
            count_query = count_query.where(Artifact.stage_name == stage_name)

        total_result = await session.execute(count_query)
        total = len(total_result.fetchall())

        sortable = {
            "created_at": Artifact.created_at,
            "stage_name": Artifact.stage_name,
            "status": Artifact.status,
            "duration": Artifact.duration,
            "start_time": Artifact.start_time,
        }
        sort_col = sortable.get(sort_by, Artifact.created_at)
        if sort_order == "desc":
            sort_col = sort_col.desc()
        else:
            sort_col = sort_col.asc()

        query = (
            query.order_by(sort_col)
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        result = await session.execute(query)
        artifacts = list(result.scalars().all())
        return artifacts, total

    def delete_artifact_files(self, artifact_dir: Path) -> bool:
        if not artifact_dir.exists():
            return False
        for entry in artifact_dir.iterdir():
            if entry.is_file():
                entry.unlink()
        try:
            artifact_dir.rmdir()
        except OSError:
            pass
        logger.info(
            "Deleted artifact files: {path}",
            path=str(artifact_dir),
        )
        return True


artifact_manager = ArtifactManager()
