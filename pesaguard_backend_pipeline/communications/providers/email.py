from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..core.enums import CommunicationChannel
from ..core.interfaces import CommunicationProvider, NotificationRequest, ProviderMessage
from .factory import build_default_provider_for_channel
from .router import ProviderRouter
from .smtp import SmtpEmailProvider


class _BaseCloudEmailProvider(SmtpEmailProvider):
    """Enterprise cloud-email adapter shape that mirrors the repo's SMTP contract.

    Providers such as SES, SendGrid, and Mailgun can share the same provider
    envelope and validation semantics while offering a more explicit adapter name.
    """

    supported_channels = frozenset({CommunicationChannel.EMAIL})

    def __init__(self, client: Any, *, from_email: str, provider_name: str):
        super().__init__(client, from_email=from_email)
        self.name = provider_name


class SesEmailProvider(_BaseCloudEmailProvider):
    name = "ses_email"

    def __init__(self, client: Any, *, from_email: str = "no-reply@pesaguard.co.ke"):
        super().__init__(client, from_email=from_email, provider_name=self.name)


class SendGridEmailProvider(_BaseCloudEmailProvider):
    name = "sendgrid_email"

    def __init__(self, client: Any, *, from_email: str = "no-reply@pesaguard.co.ke"):
        super().__init__(client, from_email=from_email, provider_name=self.name)


class MailgunEmailProvider(_BaseCloudEmailProvider):
    name = "mailgun_email"

    def __init__(self, client: Any, *, from_email: str = "no-reply@pesaguard.co.ke"):
        super().__init__(client, from_email=from_email, provider_name=self.name)


class EmailProviderRegistry:
    """Explicit registry that names the enterprise email providers in the repo.

    It keeps the provider map stable, discoverable, and extension-friendly so
    deployments can swap from SMTP to a mock provider or a future SES/SendGrid
    gateway without changing the caller contract.
    """

    def __init__(self):
        self._providers: dict[str, type[CommunicationProvider]] = {
            "smtp_email": SmtpEmailProvider,
            "smtp": SmtpEmailProvider,
            "email_smtp": SmtpEmailProvider,
            "ses_email": SesEmailProvider,
            "ses": SesEmailProvider,
            "sendgrid_email": SendGridEmailProvider,
            "sendgrid": SendGridEmailProvider,
            "mailgun_email": MailgunEmailProvider,
            "mailgun": MailgunEmailProvider,
            "mock_email": MockEmailProvider,
            "mock": MockEmailProvider,
            "email_mock": MockEmailProvider,
        }
        self._aliases: dict[str, str] = {
            "email": "smtp_email",
            "smtp_email_provider": "smtp_email",
            "smtp_provider": "smtp_email",
            "mail_provider": "smtp_email",
            "mock_email_provider": "mock_email",
            "email_mock_provider": "mock_email",
        }

    @staticmethod
    def _normalize(name: str) -> str:
        return name.strip().lower().replace("-", "_").replace(" ", "_")

    def register(self, name: str, provider_cls: type[CommunicationProvider]) -> None:
        self._providers[self._normalize(name)] = provider_cls

    def register_alias(self, alias: str, provider_name: str) -> None:
        self._aliases[self._normalize(alias)] = self._normalize(provider_name)

    def get(self, name: str) -> type[CommunicationProvider]:
        normalized = self._normalize(name)
        resolved = self._aliases.get(normalized, normalized)
        if resolved not in self._providers:
            raise ValueError(f"unsupported explicit email provider: {name}")
        return self._providers[resolved]

    def names(self) -> list[str]:
        return sorted(self._providers)

    def supported_aliases(self) -> list[str]:
        return sorted(self._aliases)


class MockEmailProvider(SmtpEmailProvider):
    """Deterministic mock SMTP-style provider for local and test delivery.

    It adopts the same send contract and status envelope as the repository's
    provider model, which enables deterministic tests without inventing a
    separate disconnected application.
    """

    name = "mock_email"

    def __init__(self, client: Any | None = None, *, from_email: str = "noreply@pesaguard.local"):
        self.client = client or _MockEmailGateway()
        self.from_email = from_email

    def _send(self, request: NotificationRequest) -> ProviderMessage:
        recipient = self.validate_recipient(request.channel, request.recipient)
        subject = str((request.variables or {}).get("subject") or "PesaGuard notification")
        message = {
            "to": recipient,
            "from_email": self.from_email,
            "subject": subject,
            "body": request.message,
            "idempotency_key": request.idempotency_key,
        }
        response = self.client.send_message(message)
        if not isinstance(response, dict) or not response.get("message_id"):
            raise RuntimeError("mock email gateway rejected message")
        return ProviderMessage(
            provider=self.name,
            provider_message_id=str(response.get("message_id")),
            status="accepted",
            raw_response=response,
        )


class _MockEmailGateway:
    def send_message(self, message: dict[str, Any]) -> dict[str, Any]:
        return {"message_id": "mock-sent-1", "status": "accepted", "to": message.get("to")}


@dataclass(frozen=True)
class EmailProviderConfig:
    """Configuration carrier for email provider selection.

    It remains compatible with the existing repo's dependency-injected
    communication provider pattern while naming the requested provider object
    directly in a way that is discoverable for operators and tests.
    """

    provider: str = "smtp_email"
    from_email: str = "no-reply@pesaguard.co.ke"
    gateway_client: Any | None = None


class EmailProviderFactory:
    """Create the email provider using the repository's transport contract."""

    def __init__(self, gateway_client: Any | None = None, config: EmailProviderConfig | None = None, registry: EmailProviderRegistry | None = None):
        self.gateway_client = gateway_client
        self.config = config or EmailProviderConfig()
        self.registry = registry or EmailProviderRegistry()

    def create(self) -> CommunicationProvider:
        provider_name = self.registry._normalize(self.config.provider)
        if provider_name not in self.registry.names():
            raise ValueError(f"unsupported explicit email provider: {self.config.provider}")
        provider_cls = self.registry.get(provider_name)
        if provider_name in {"smtp_email", "smtp", "email_smtp", "ses_email", "ses", "sendgrid_email", "sendgrid", "mailgun_email", "mailgun"}:
            if self.gateway_client is None:
                raise RuntimeError("email provider requires an injected gateway client")
            return provider_cls(self.gateway_client, from_email=self.config.from_email)
        if provider_name in {"mock_email", "mock", "email_mock"}:
            return provider_cls(self.gateway_client, from_email=self.config.from_email)
        raise ValueError(f"unsupported explicit email provider: {self.config.provider}")


class EmailRouter(ProviderRouter):
    """Compatibility router that routes through a configured provider map.

    The router accepts the repository's existing channel ordering format and
    adds a stable compatibility gateway with an explicit route/send API for
    the enterprise-facing email object names requested by the product.
    """

    def __init__(self, providers: dict[str, CommunicationProvider], order: dict[CommunicationChannel, list[str]], *, failure_threshold: int = 3, cooldown_seconds: int = 60, half_open_max_calls: int = 2):
        super().__init__(providers, order, failure_threshold=failure_threshold, cooldown_seconds=cooldown_seconds, half_open_max_calls=half_open_max_calls)

    def route(self, request: NotificationRequest, *, provider_hint: str | None = None) -> ProviderMessage:
        if provider_hint:
            name = self.validate_provider_name(provider_hint)
            if name in self.providers:
                return self.providers[name].send(request)
        return self.send(request)

    def validate_provider_name(self, name: str) -> str:
        normalized = EmailProviderRegistry._normalize(name)
        if normalized in self.providers:
            return normalized
        raise ValueError(f"unsupported explicit email provider: {name}")

    def registered_names(self) -> list[str]:
        return sorted(self.providers)


class EmailProviderAnalytics:
    """Analytics-friendly provider tracker that can stay in-memory or report through the
    repository's persisted CommunicationAttempt/Notification model when a Session is supplied.

    It aggregates runtime outcomes into a provider-scoped format that can be consumed by
    dashboards, operator UIs, and health reporting objects without forcing a separate
    disconnected analytics database.
    """

    def __init__(self, session: Session | None = None):
        self.session = session
        self._stats: dict[str, dict[str, Any]] = {}

    def _ensure(self, provider: str) -> dict[str, Any]:
        provider_key = EmailProviderRegistry._normalize(provider)
        if provider_key not in self._stats:
            self._stats[provider_key] = {
                "successes": 0,
                "failures": 0,
                "latencies_ms": [],
                "errors": [],
                "costs": [],
            }
        return self._stats[provider_key]

    def record_success(self, provider: str, *, latency_ms: int = 0, cost: dict[str, Any] | None = None, notification_id: str | None = None) -> None:
        stats = self._ensure(provider)
        stats["successes"] += 1
        stats["latencies_ms"].append(latency_ms)
        if cost:
            stats["costs"].append(cost)
        if self.session is not None and notification_id:
            try:
                from ..models import CommunicationNotification
                notification = self.session.query(CommunicationNotification).filter_by(id=notification_id).one_or_none()
                if notification is not None:
                    notification.metadata_json = {**dict(notification.metadata_json or {}), "last_provider_latency_ms": latency_ms}
            except Exception:
                pass

    def record_failure(self, provider: str, error_code: str = "PROVIDER_FAILURE", *, latency_ms: int = 0, cost: dict[str, Any] | None = None, notification_id: str | None = None) -> None:
        stats = self._ensure(provider)
        stats["failures"] += 1
        stats["errors"].append(error_code)
        stats["latencies_ms"].append(latency_ms)
        if cost:
            stats["costs"].append(cost)
        if self.session is not None and notification_id:
            try:
                from ..models import CommunicationNotification
                notification = self.session.query(CommunicationNotification).filter_by(id=notification_id).one_or_none()
                if notification is not None:
                    notification.failure_code = error_code
                    notification.metadata_json = {**dict(notification.metadata_json or {}), "last_provider_latency_ms": latency_ms, "last_provider_error": error_code}
            except Exception:
                pass

    def snapshot(self, session: Session | None = None) -> dict[str, Any]:
        providers: dict[str, Any] = {}
        for provider, stats in self._stats.items():
            total = stats["successes"] + stats["failures"]
            latencies = stats["latencies_ms"]
            successes = stats["successes"]
            failures = stats["failures"]
            providers[provider] = {
                "successes": successes,
                "failures": failures,
                "delivery_rate": round(successes / total, 4) if total else 1.0,
                "error_codes": list(stats["errors"]),
                "average_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
                "costs": stats["costs"],
            }
        if session is not None:
            try:
                from ..providers.health import provider_health_snapshot
                for provider, stats in providers.items():
                    try:
                        health = provider_health_snapshot(session, provider)
                        stats["health"] = {
                            "score": health.get("score"),
                            "level": health.get("level"),
                            "delivery_rate": health.get("delivery_rate"),
                            "average_latency_ms": health.get("average_latency_ms"),
                        }
                    except Exception:
                        pass
            except Exception:
                pass
        return {"providers": providers}


class EmailProviderHealth:
    """Health object for provider health snapshots without making claims."""

    def __init__(self, score: float = 100.0):
        self.score = score
        self.samples = 0
        self.failures = 0
        self.latencies_ms: list[int] = []

    def register_result(self, provider: str, failed: bool = False, latency_ms: int = 0) -> None:
        self.samples += 1
        if failed:
            self.failures += 1
            self.score = max(0.0, self.score - 5.0)
        else:
            self.score = min(100.0, self.score + 0.5)
        if latency_ms >= 0:
            self.latencies_ms.append(latency_ms)

    def snapshot(self) -> dict[str, Any]:
        return {
            "provider": "smtp_email",
            "health_score": self.score,
            "status": "healthy" if self.score >= 90 else "degraded",
            "samples": self.samples,
            "failures": self.failures,
            "average_latency_ms": round(sum(self.latencies_ms) / len(self.latencies_ms), 1) if self.latencies_ms else 0,
        }
