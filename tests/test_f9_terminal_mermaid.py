import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MMD = ROOT / "docs/generated/f9-terminal-pcap-replay-evidence-flow.mmd"
MARKDOWN = ROOT / "docs/generated/f9-terminal-pcap-replay-evidence-flow.md"


class F9TerminalMermaidTests(unittest.TestCase):
    def test_markdown_embeds_exact_mermaid_source(self):
        source = MMD.read_text(encoding="utf-8").strip()
        markdown = MARKDOWN.read_text(encoding="utf-8")
        match = re.search(r"```mermaid\n(.*?)\n```", markdown, re.DOTALL)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1).strip(), source)

    def test_subgraphs_are_balanced_and_ids_are_unique(self):
        source = MMD.read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"^\s*subgraph\s+", source, re.MULTILINE)), 4)
        self.assertEqual(len(re.findall(r"^\s*end\s*$", source, re.MULTILINE)), 4)
        ids = re.findall(r'^\s*([A-Z][A-Z0-9]*)\["', source, re.MULTILINE)
        self.assertEqual(len(ids), len(set(ids)))

    def test_required_evidence_boundaries_are_visible(self):
        source = MMD.read_text(encoding="utf-8")
        for required in (
            "đúng 9 packet",
            "thường 180 giây",
            "nids_demo_replay",
            "tcpreplay-edit 1×",
            "passive 1 RX / 0 TX",
            "không gộp mẫu F9 với Terminal",
            "test partition luôn sealed",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
