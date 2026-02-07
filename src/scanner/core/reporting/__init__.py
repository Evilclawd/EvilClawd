"""Report generation engine with Jinja2 templates (REPT-01 through REPT-04).

Provides structured markdown pentest reports from vulnerability findings
and exploit results, with evidence validation, source attribution,
and HTML export capabilities.

Provides:
- ReportGenerator: Main report generation class
- export_html: HTML export from markdown
"""

from .generator import ReportGenerator
from .export import export_html

__all__ = ["ReportGenerator", "export_html"]
