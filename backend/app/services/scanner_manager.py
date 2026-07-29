from typing import Optional

from loguru import logger

from app.services.scanner import OpenVASScanner, VulnerabilityScanner


class ScannerManager:
    def __init__(self):
        self._scanners: dict[str, VulnerabilityScanner] = {}

    def register(self, name: str, scanner: VulnerabilityScanner) -> None:
        self._scanners[name] = scanner
        logger.info("Scanner registered: {name}", name=name)

    def unregister(self, name: str) -> None:
        self._scanners.pop(name, None)
        logger.info("Scanner unregistered: {name}", name=name)

    def get_scanner(self, name: str) -> Optional[VulnerabilityScanner]:
        return self._scanners.get(name)

    def list_scanners(self) -> list[str]:
        return list(self._scanners.keys())

    async def connect_scanner(self, name: str, **kwargs) -> bool:
        scanner = self.get_scanner(name)
        if not scanner:
            logger.error("Scanner not found: {name}", name=name)
            return False
        if hasattr(scanner, "configure"):
            scanner.configure(**kwargs)
        return await scanner.connect()

    async def disconnect_scanner(self, name: str) -> bool:
        scanner = self.get_scanner(name)
        if not scanner:
            return False
        return await scanner.disconnect()

    async def run_scan(
        self,
        scanner_name: str,
        target: str,
        ports: Optional[str] = None,
        scan_profile: Optional[str] = None,
    ) -> str:
        scanner = self.get_scanner(scanner_name)
        if not scanner:
            raise ValueError(f"Scanner '{scanner_name}' not registered")
        return await scanner.scan(target=target, ports=ports, scan_profile=scan_profile)

    async def cancel_scan(self, scanner_name: str, scan_id: str) -> bool:
        scanner = self.get_scanner(scanner_name)
        if not scanner:
            return False
        return await scanner.cancel(scan_id)

    async def get_scan_status(self, scanner_name: str, scan_id: str):
        scanner = self.get_scanner(scanner_name)
        if not scanner:
            return None
        return await scanner.get_status(scan_id)

    async def fetch_scan_results(self, scanner_name: str, scan_id: str):
        scanner = self.get_scanner(scanner_name)
        if not scanner:
            return None
        return await scanner.fetch_results(scan_id)


scanner_manager = ScannerManager()
scanner_manager.register("openvas", OpenVASScanner())
