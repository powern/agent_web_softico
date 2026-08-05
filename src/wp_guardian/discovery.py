from pathlib import Path

from .config import GuardianConfig
from .models import Site


def is_wordpress(path: Path) -> bool:
    return (path / "wp-config.php").is_file() and (path / "wp-admin").is_dir()


def discover_sites(config: GuardianConfig) -> list[Site]:
    sites: list[Site] = []
    if not config.sites_root.is_dir():
        return sites
    for domain_dir in sorted(config.sites_root.iterdir()):
        if not domain_dir.is_dir():
            continue
        domain = domain_dir.name
        if config.include and domain not in config.include:
            continue
        if domain in config.exclude:
            continue
        public_html = domain_dir / "public_html"
        if is_wordpress(public_html):
            sites.append(Site(domain=domain, path=public_html))
    return sites
