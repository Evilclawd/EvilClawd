"""HTML export from markdown reports.

Converts markdown pentest reports to styled HTML documents
for easy sharing and viewing in web browsers.
"""

import markdown


def export_html(markdown_content: str, output_path: str) -> str:
    """Export markdown report to styled HTML document.

    Converts markdown to HTML with table, code block, and TOC support,
    and wraps in a styled HTML document with CSS.

    Args:
        markdown_content: Markdown report string
        output_path: Path to write HTML file

    Returns:
        Path to written HTML file

    Example:
        >>> report_md = generator.generate(target="https://example.com", findings=[...])
        >>> html_path = export_html(report_md, "/tmp/report.html")
    """
    # Convert markdown to HTML with extensions
    html_body = markdown.markdown(
        markdown_content,
        extensions=["tables", "fenced_code", "toc"],
    )

    # Wrap in styled HTML document
    html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }}

        h1, h2, h3, h4 {{
            color: #2c3e50;
            margin-top: 1.5em;
        }}

        h1 {{
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}

        h2 {{
            border-bottom: 2px solid #95a5a6;
            padding-bottom: 8px;
        }}

        h3 {{
            color: #e74c3c;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}

        th {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }}

        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}

        code {{
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 2px 6px;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
        }}

        pre {{
            background-color: #282c34;
            color: #abb2bf;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            margin: 15px 0;
        }}

        pre code {{
            background-color: transparent;
            border: none;
            padding: 0;
            color: inherit;
        }}

        ul, ol {{
            margin: 10px 0;
            padding-left: 30px;
        }}

        li {{
            margin: 5px 0;
        }}

        strong {{
            color: #2c3e50;
        }}

        hr {{
            border: none;
            border-top: 2px solid #bdc3c7;
            margin: 30px 0;
        }}

        blockquote {{
            border-left: 4px solid #3498db;
            margin: 15px 0;
            padding-left: 15px;
            color: #555;
        }}

        .severity-critical {{
            color: #c0392b;
            font-weight: bold;
        }}

        .severity-high {{
            color: #e67e22;
            font-weight: bold;
        }}

        .severity-medium {{
            color: #f39c12;
            font-weight: bold;
        }}

        .severity-low {{
            color: #27ae60;
            font-weight: bold;
        }}

        .severity-info {{
            color: #3498db;
            font-weight: bold;
        }}
    </style>
</head>
<body>
{html_body}
</body>
</html>
"""

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_document)

    return output_path
