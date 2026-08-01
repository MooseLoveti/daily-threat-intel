import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import daily_brief


class DailyBriefTests(unittest.TestCase):
    def setUp(self):
        self.candidates = {
            "generated_at": "2026-08-01T00:00:00+00:00",
            "cutoff_at": "2026-07-31T00:00:00+00:00",
            "source_names": ["The Record"],
            "articles": [
                {
                    "id": "therecord:1234",
                    "source_key": "therecord",
                    "source_name": "The Record",
                    "title": "Example incident",
                    "url": "https://therecord.media/example",
                    "published_at": "2026-07-31T10:00:00+00:00",
                    "summary": "Example source summary",
                    "excerpt": "Example source excerpt",
                }
            ],
        }

    def test_canonical_url_removes_tracking_parameters(self):
        result = daily_brief.canonical_url("https://example.test/a/?utm_source=x&ref=y&id=7#section")
        self.assertEqual(result, "https://example.test/a?id=7")

    def test_validate_items_rejects_unknown_candidate_urls(self):
        response = {
            "items": [
                {
                    "candidate_ids": ["therecord:1234", "unknown:999"],
                    "primary_category": "incident",
                    "secondary_categories": ["actor", "not-a-category"],
                    "title_ja": "例示インシデント",
                    "summary_ja": ["確認済みの情報だけを要約する。"],
                    "why_it_matters_ja": "影響確認が必要。",
                    "confidence": "confirmed",
                    "evidence": "reporting",
                }
            ]
        }
        items = daily_brief.validate_items(response, self.candidates)
        self.assertEqual(items[0]["candidate_ids"], ["therecord:1234"])
        self.assertEqual(items[0]["secondary_categories"], ["actor"])

    def test_render_only_links_to_collected_source(self):
        response = {
            "items": [
                {
                    "candidate_ids": ["therecord:1234"],
                    "primary_category": "incident",
                    "secondary_categories": [],
                    "title_ja": "例示インシデント",
                    "summary_ja": ["例示として短く要約する。"],
                    "why_it_matters_ja": "確認が必要。",
                    "confidence": "reported",
                    "evidence": "reporting",
                }
            ]
        }
        markdown = daily_brief.render_markdown(daily_brief.validate_items(response, self.candidates), self.candidates, "Asia/Tokyo")
        self.assertIn("https://therecord.media/example", markdown)
        self.assertNotIn("unknown:999", markdown)

    def test_empty_response_is_valid(self):
        parsed = daily_brief.extract_json(json.dumps({"items": []}))
        self.assertEqual(parsed["items"], [])


if __name__ == "__main__":
    unittest.main()

