import json

import gradio as gr
import requests

from commons.logger import get_logger

logger = get_logger(__name__)

API_URL = "http://127.0.0.1:8000/analyze"

DEFAULT_JSON = json.dumps(
    {
        "incident_id": "INC-2025-0001",
        "timestamp": "2025-06-01T12:00:00Z",
        "summary": "Suspicious login attempts on production server",
        "description": "Multiple failed logins followed by a successful root login.",
        "affected_assets": [
            {
                "name": "prod-server-1",
                "ip": "10.0.0.5",
                "os": "Ubuntu 20.04",
                "software": [{"name": "OpenSSH", "version": "8.2"}],
                "role": "web server",
            },
        ],
        "observed_ttps": ["T1110", "T1059.001"],
        "ioc_ips": ["192.168.1.10"],
        "ioc_usernames": ["admin", "root"],
        "inferred_software": ["ssh"],
        "inferred_cves": ["CVE-2020-15778"],
        "initial_findings": "The attacker gained access using a known vulnerability.",
    },
    indent=2,
)


def analyze_incident(json_input: str):
    try:
        parsed = json.loads(json_input)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"

    try:
        response = requests.post(API_URL, json=parsed, timeout=30)
        response.raise_for_status()
        return response.json().get("report", "No report returned.")
    except requests.RequestException as e:
        return f"Request failed: {e}"


with gr.Blocks(title="Security Analyzer Client") as demo:
    gr.Markdown("## Incident Analyzer Client")
    with gr.Row():
        json_input = gr.Code(
            label="Incident JSON",
            language="json",
            value=DEFAULT_JSON,
            lines=20,
        )
    report_output = gr.Textbox(label="Security Report", lines=20)

    analyze_btn = gr.Button("Analyze Incident")

    analyze_btn.click(fn=analyze_incident, inputs=[json_input], outputs=[report_output])


def launch_gradio() -> None:
    logger.info("Starting Gradio client...")
    demo.launch()
