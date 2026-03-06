# Chat Memory Compactor
#
# Automatically compacts chat history when the accumulated token count
# exceeds _TOKEN_THRESHOLD. Uses Haiku to summarize old messages, then:
#   - Stores a compaction marker in securechat.db
#   - Writes a markdown memory log to data/chat_memory/
#   - Appends a 2-sentence summary to data/chat_memory/index.md
#
# After compaction, _build_history in ai_bridge uses:
#   [summary_as_context] + last 4 messages

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    from .chat_store import ChatStore
    from .message import ChatMessage

logger = logging.getLogger(__name__)

_TOKEN_THRESHOLD = 7_000    # compact at 7K tokens; keeps context cheap
_CHARS_PER_TOKEN = 3.8  # conservative estimate for English + JSON text
_MEMORY_DIR = Path("data/chat_memory")
_INDEX_FILE = _MEMORY_DIR / "index.md"
_HAIKU_MODEL = "claude-haiku-4-5-20251001"

# Minimum messages before compaction makes sense (must be > 5 to leave last-5)
_MIN_MESSAGES_TO_COMPACT = 8

# Target summary size: ~5K tokens so post-compaction context stays small
_SUMMARY_MAX_TOKENS = 5_000

# Number of recent messages to preserve verbatim after compaction
_KEEP_LAST_N = 5


def _estimate_tokens(chars: int) -> int:
    return max(0, int(chars / _CHARS_PER_TOKEN))


class MemoryCompactor:
    """Manages automatic compaction of chat history for long-running conversations.

    When accumulated tokens (since last compaction) exceed _TOKEN_THRESHOLD,
    calls Haiku to summarize the old messages and stores a compaction marker.
    Future AI context is built as: [summary] + last 4 messages.

    Args:
        client: anthropic.AsyncAnthropic instance (must be available).
        store:  ChatStore instance.
    """

    def __init__(self, client, store: "ChatStore"):
        self._client = client
        self._store = store

    # ── Public API ──────────────────────────────────────────────────────

    def should_compact(self) -> bool:
        """Return True if accumulated tokens since last compaction exceed threshold."""
        # Read user-configured threshold (falls back to module-level constant)
        threshold = _TOKEN_THRESHOLD
        try:
            from ..core.user_preferences import get_user_preferences
            raw = get_user_preferences().get("ai.compaction_tokens")
            if raw:
                threshold = max(5_000, min(500_000, int(raw)))
        except Exception:
            pass

        chars = self._store.total_content_length_since_compaction()
        estimated = _estimate_tokens(chars)
        if estimated >= threshold:
            logger.info(
                "Memory compaction triggered: ~%d tokens since last compaction (threshold=%d)",
                estimated, threshold,
            )
            return True
        return False

    async def compact(self) -> Optional[str]:
        """Run compaction. Returns the summary text, or None if skipped/failed.

        Steps:
        1. Load all messages since last compaction (or all time).
        2. Call Haiku to summarize all-but-last-5 into a ~5K token summary.
        3. Write memory log file + update index (this IS the memorize step).
        4. Store compaction marker in DB so _build_history uses summary + last-5.
        """
        all_messages = self._store.get_messages_for_compaction()

        if len(all_messages) < _MIN_MESSAGES_TO_COMPACT:
            logger.debug(
                "Skipping compaction: only %d messages (need %d+)",
                len(all_messages),
                _MIN_MESSAGES_TO_COMPACT,
            )
            return None

        to_summarize = all_messages[:-_KEEP_LAST_N]
        last_n = all_messages[-_KEEP_LAST_N:]

        logger.info("Compacting %d messages into summary (keeping last %d)", len(to_summarize), _KEEP_LAST_N)

        try:
            full_summary, short_summary = await self._summarize(to_summarize)
        except Exception:
            logger.exception("Memory compaction: Haiku summarization failed")
            return None

        # Write memory log + update index — this is the long-term "memorize" step
        try:
            log_path = self._write_memory_log(full_summary, to_summarize)
            self._update_index(log_path.name, short_summary)
        except Exception:
            logger.exception("Memory compaction: failed to write memory log")
            # Non-fatal — continue with DB marker

        # Store compaction marker in DB
        try:
            self._store_compaction_marker(full_summary, len(to_summarize), last_n)
        except Exception:
            logger.exception("Memory compaction: failed to store DB marker")
            return None

        logger.info(
            "Memory compaction complete: %d messages summarized, %d kept verbatim",
            len(to_summarize), len(last_n),
        )
        return full_summary

    def get_latest_summary(self) -> Optional[str]:
        """Return the most recent compaction summary text, or None."""
        return self._store.get_latest_compaction_summary()

    def get_latest_marker_timestamp(self) -> Optional[str]:
        """Return the timestamp of the latest compaction marker, or None."""
        return self._store.get_latest_compaction_timestamp()

    # ── Internal ────────────────────────────────────────────────────────

    async def _summarize(self, messages: List["ChatMessage"]) -> Tuple[str, str]:
        """Call Haiku to produce a full + 2-sentence summary.

        Returns (full_summary, two_sentence_summary).
        """
        lines = []
        for m in messages:
            role = m.from_id.upper()
            text = m.text or json.dumps(m.payload)
            if len(text) > 800:
                text = text[:800] + "...[truncated]"
            lines.append(f"[{role}]: {text}")

        transcript = "\n".join(lines)

        prompt = (
            "You are summarizing a cybersecurity chat session for Citadel Archer, "
            "an AI-centric security dashboard.\n\n"
            "CONVERSATION TRANSCRIPT:\n"
            f"{transcript}\n\n"
            "Please provide:\n\n"
            "1. FULL SUMMARY (3-8 paragraphs): Capture all important context -- "
            "security events discussed, decisions made, defensive actions taken, "
            "threat findings, VPS agent activity, specific IP addresses, hostnames, "
            "threat types, and any ongoing investigations. Include enough detail to "
            "allow the AI to continue the conversation seamlessly.\n\n"
            "2. TWO SENTENCE SUMMARY: A brief description of this session, suitable "
            "for a memory index that the AI reads at the start of every conversation.\n\n"
            "Format your response EXACTLY as:\n"
            "FULL_SUMMARY:\n"
            "[your full summary here]\n\n"
            "TWO_SENTENCE_SUMMARY:\n"
            "[your two sentence summary here]"
        )

        response = await asyncio.wait_for(
            self._client.messages.create(
                model=_HAIKU_MODEL,
                max_tokens=_SUMMARY_MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=90,
        )

        raw = response.content[0].text if response.content else ""

        full_summary = raw
        short_summary = ""

        if "FULL_SUMMARY:" in raw and "TWO_SENTENCE_SUMMARY:" in raw:
            parts = raw.split("TWO_SENTENCE_SUMMARY:", 1)
            full_summary = parts[0].replace("FULL_SUMMARY:", "").strip()
            short_summary = parts[1].strip()
        elif "TWO_SENTENCE_SUMMARY:" in raw:
            parts = raw.split("TWO_SENTENCE_SUMMARY:", 1)
            short_summary = parts[1].strip()

        if not short_summary:
            short_summary = (
                full_summary[:200] + "..." if len(full_summary) > 200 else full_summary
            )

        return full_summary, short_summary

    def _write_memory_log(
        self, summary: str, messages: List["ChatMessage"]
    ) -> Path:
        """Write a markdown memory log. Returns the path."""
        _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        filename = f"session_{now.strftime('%Y%m%d_%H%M%S')}.md"
        log_path = _MEMORY_DIR / filename

        period_start = messages[0].timestamp[:10] if messages else "unknown"
        period_end = messages[-1].timestamp[:10] if messages else "unknown"

        content = (
            f"# Citadel Archer Chat Memory Log\n\n"
            f"**Date:** {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"**Messages Summarized:** {len(messages)}\n"
            f"**Period:** {period_start} to {period_end}\n\n"
            f"## Summary\n\n{summary}\n"
        )

        log_path.write_text(content, encoding="utf-8")
        logger.info("Memory log written: %s", log_path)
        return log_path

    def _update_index(self, log_filename: str, short_summary: str) -> None:
        """Append an entry to the memory index file."""
        _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        # Sanitize short_summary for table cell (remove pipe characters)
        safe_summary = short_summary.replace("|", "-").replace("\n", " ")
        entry = f"| {now} | [{log_filename}]({log_filename}) | {safe_summary} |\n"

        if not _INDEX_FILE.exists():
            header = (
                "# Citadel Archer Chat Memory Index\n\n"
                "Long-term memory for Guardian AI. "
                "Each entry is a compacted session summary.\n\n"
                "| Date | Log File | Summary |\n"
                "|------|----------|---------|\n"
            )
            _INDEX_FILE.write_text(header + entry, encoding="utf-8")
        else:
            with _INDEX_FILE.open("a", encoding="utf-8") as f:
                f.write(entry)

        logger.info("Memory index updated: %s", _INDEX_FILE)

    def _store_compaction_marker(
        self,
        summary: str,
        compacted_count: int,
        last_n: List["ChatMessage"],
    ) -> None:
        """Persist a compaction marker message to the DB.

        The marker is stored with a timestamp 1 microsecond BEFORE last_n[0] so
        that get_messages_for_compaction (timestamp > marker_ts) naturally includes
        all of last_n in future context queries.  Without this, last_n would have
        timestamps BEFORE the marker and be permanently excluded after compaction.
        """
        from .message import ChatMessage, MessageType, PARTICIPANT_CITADEL

        resumed_from = last_n[0].timestamp if last_n else None

        # Place marker just before last_n[0] so post-compaction queries include them
        if resumed_from:
            try:
                marker_ts = (
                    datetime.fromisoformat(resumed_from) - timedelta(microseconds=1)
                ).isoformat()
            except Exception:
                marker_ts = datetime.now(timezone.utc).isoformat()
        else:
            marker_ts = datetime.now(timezone.utc).isoformat()

        marker = ChatMessage(
            from_id=PARTICIPANT_CITADEL,
            to_id="user",
            msg_type=MessageType.RESPONSE,
            timestamp=marker_ts,
            payload={
                "text": summary,
                "compaction_summary": True,
                "compacted_count": compacted_count,
                "resumed_from": resumed_from,
            },
        )
        self._store.save(marker)


# ── Module-level helpers ─────────────────────────────────────────────────


def load_memory_index() -> str:
    """Return the contents of index.md for injection into the system prompt.

    Returns an empty string if no index exists yet.
    """
    if not _INDEX_FILE.exists():
        return ""
    try:
        return _INDEX_FILE.read_text(encoding="utf-8")
    except Exception:
        logger.warning("Failed to read memory index", exc_info=True)
        return ""
