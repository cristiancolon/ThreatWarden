from datetime import datetime
from .base import Ingestor, RawVulnerability


class CISAKEVIngestor(Ingestor):
    def source_name(self) -> str:
        return "cisa_kev"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        # TODO: Implement CISA KEV ingestor
        pass
