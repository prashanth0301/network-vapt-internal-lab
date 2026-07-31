from typing import Optional

from loguru import logger

from app.services.cve_provider import CVEProvider, CVEResult, NVDProvider, ProviderStatus


class CVEProviderManager:
    def __init__(self):
        self._providers: dict[str, CVEProvider] = {}

    def register(self, name: str, provider: CVEProvider) -> None:
        self._providers[name] = provider
        logger.info("CVE provider registered: {name}", name=name)

    def unregister(self, name: str) -> None:
        self._providers.pop(name, None)
        logger.info("CVE provider unregistered: {name}", name=name)

    def get_provider(self, name: str) -> Optional[CVEProvider]:
        return self._providers.get(name)

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    async def connect_all(self) -> dict[str, bool]:
        results = {}
        for name, provider in self._providers.items():
            results[name] = await provider.connect()
        return results

    async def disconnect_all(self) -> dict[str, bool]:
        results = {}
        for name, provider in self._providers.items():
            results[name] = await provider.disconnect()
        return results

    async def health_all(self) -> dict[str, ProviderStatus]:
        return {
            name: await provider.health()
            for name, provider in self._providers.items()
        }

    async def lookup_cve(
        self, cve_id: str, provider_name: Optional[str] = None
    ) -> Optional[CVEResult]:
        if provider_name:
            provider = self.get_provider(provider_name)
            if not provider:
                logger.error("Provider not found: {name}", name=provider_name)
                return None
            return await provider.lookup_cve(cve_id)
        for name, provider in self._providers.items():
            result = await provider.lookup_cve(cve_id)
            if result is not None:
                return result
        return None

    async def lookup_multiple(
        self, cve_ids: list[str], provider_name: Optional[str] = None
    ) -> dict[str, Optional[CVEResult]]:
        results: dict[str, Optional[CVEResult]] = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.lookup_cve(cve_id, provider_name)
        return results


cve_provider_manager = CVEProviderManager()
cve_provider_manager.register("nvd", NVDProvider())
