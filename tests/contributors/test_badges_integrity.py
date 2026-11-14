import xml.etree.ElementTree as ET
from pathlib import Path


BADGES_DIR = Path(__file__).resolve().parents[2] / "contributor_system" / "badges"

EXPECTED = [
    "first_contributor",
    "code_contributor",
    "bug_hunter",
    "documentation_hero",
    "feature_builder",
    "testing_champion",
    "top_contributor",
    "core_maintainer",
    "community_hero",
    "open_source_advocate",
]


def test_all_badge_files_exist():
    for name in EXPECTED:
        assert (BADGES_DIR / f"{name}.svg").is_file(), name


def test_badges_parse_and_have_viewbox_and_title():
    for name in EXPECTED:
        svg = ET.parse(BADGES_DIR / f"{name}.svg")  # noqa: S314 - trusted local files
        root = svg.getroot()
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox") == "0 0 512 640"
        title = root.find("{http://www.w3.org/2000/svg}title")
        assert title is not None
        assert (title.text or "").strip()


def test_badges_transparent_no_background_rect():
    for name in EXPECTED:
        root = ET.parse(BADGES_DIR / f"{name}.svg").getroot()  # noqa: S314 - trusted local files
        ns = "{http://www.w3.org/2000/svg}"
        for rect in root.iter(f"{ns}rect"):
            w = rect.attrib.get("width")
            h = rect.attrib.get("height")
            # A full-canvas opaque rect would violate transparency.
            full_w = w in ("512", "100%")
            full_h = h in ("640", "100%")
            assert not (full_w and full_h), f"{name} has a background rect"


def test_readme_documents_embedding():
    text = (BADGES_DIR / "README.md").read_text(encoding="utf-8")
    assert "raw/main/contributor_system/badges" in text
