from datetime import datetime
from .base import Ingestor, RawVulnerability


class EPSSIngestor(Ingestor):
    def source_name(self) -> str:
        return "epss"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        # TODO: Implement EPSS ingestor
        pass
