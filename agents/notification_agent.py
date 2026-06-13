import logging
import requests
from pathlib import Path
from typing import Optional
import json

from config import DISCORD_WEBHOOK_URL
from agents.correlation_agent import CorrelationResult

logger = logging.getLogger(__name__)

class NotificationAgent:
    """
    Dispatches rich notifications to the SOC via external channels (e.g., Discord).
    """

    def __init__(self, webhook_url: Optional[str] = DISCORD_WEBHOOK_URL):
        self.webhook_url = webhook_url

    def send_alert(self, alert: CorrelationResult, pdf_path: Optional[Path] = None, stix_path: Optional[Path] = None) -> bool:
        """
        Send a rich embed alert to the configured Discord webhook.
        If no webhook is configured, logs gracefully.
        """
        import config
        webhook = self.webhook_url or config.DISCORD_WEBHOOK_URL
        if not webhook:
            logger.warning(f"NotificationAgent: Webhook URL not configured. Skipping alert dispatch for {alert.record_id}.")
            return False

        logger.info(f"NotificationAgent: Dispatching alert {alert.record_id} to webhook.")

        # Determine embed color based on priority
        color = 0x3498db # Default Blue
        if alert.priority == 'CRITICAL':
            color = 0xe74c3c # Red
        elif alert.priority == 'HIGH':
            color = 0xe67e22 # Orange
        elif alert.priority == 'MEDIUM':
            color = 0xf1c40f # Yellow

        embed = {
            "title": f"🚨 {alert.priority} Threat Detected: Auto-Containment Triggered",
            "description": "BankSentinel has detected a high-confidence threat campaign and initiated automated containment procedures.",
            "color": color,
            "fields": [
                {"name": "Incident ID", "value": alert.campaign_ticket_id or str(alert.record_id), "inline": True},
                {"name": "Composite Risk Score", "value": f"{alert.crs:.4f}", "inline": True},
                {"name": "Timestamp (UTC)", "value": alert.timestamp.isoformat(), "inline": False},
                {"name": "Source IP", "value": f"`{alert.src_ip}`", "inline": True},
                {"name": "Destination IP", "value": f"`{alert.dst_ip}`", "inline": True},
                {"name": "Agents Fired", "value": ", ".join(alert.agents_fired) if alert.agents_fired else "None", "inline": False}
            ],
            "footer": {
                "text": "BankSentinel Multi-Agent IDS • PCI-DSS 10.3 Compliant"
            }
        }

        payload = {"embeds": [embed]}
        files = {}

        try:
            # Prepare files if they exist
            if pdf_path and pdf_path.exists():
                files['pdf'] = (pdf_path.name, open(pdf_path, 'rb'), 'application/pdf')
            if stix_path and stix_path.exists():
                files['stix'] = (stix_path.name, open(stix_path, 'rb'), 'application/json')

            if files:
                # When sending files, payload must be in 'payload_json' field
                response = requests.post(
                    webhook,
                    data={"payload_json": json.dumps(payload)},
                    files=files,
                    timeout=5
                )
            else:
                response = requests.post(
                    webhook,
                    json=payload,
                    timeout=5
                )

            response.raise_for_status()
            logger.info("NotificationAgent: Alert dispatched successfully.")
            return True

        except Exception as e:
            logger.error(f"NotificationAgent: Failed to dispatch alert: {e}")
            return False
        finally:
            for f in files.values():
                try:
                    f[1].close()
                except:
                    pass
