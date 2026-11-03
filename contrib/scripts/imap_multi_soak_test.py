#!/usr/bin/env python3
"""
IMAP Active-Active Multi-Mailbox Round-Robin / Striping Soak & Benchmark Test
=============================================================================
Экспериментальная проверка архитектуры Раздела 9 (`contrib/docs/imap.ru.md`)
для ANet ASTP-over-IMAPS:993 без модификации боевого Rust-кода:

  1. Пул из N >= 1 независимых почтовых ящиков (по 4 IMAPS-соединения на ящик:
     CLI_WRITER[i] + CLI_READER[i] и SRV_READER[i] + SRV_WRITER[i]).
  2. Центральный диспетчер Uplink и центральный диспетчер Downlink по алгоритму
     Self-Clocking Round-Robin (Fast Path по rr_cursor + All-Busy гонка за первым
     освободившимся воркером без Head-of-Line блокировки).
  3. Динамическая привязка вторичных ящиков на сервере (SessionMailboxPool +
     Mailbox Binding Frame) и Zero-Loss Retry при сбое отдельного ящика.
  4. Строгая изоляция UID (last_seen_uid, ленивый пакетный UID EXPUNGE по 25 шт.
     или по тайм-ауту тишины 1500 мс) внутри каждого ящика.
  5. Поддержка LITERAL+ (1-RTT APPEND без ожидания '+ go ahead') и адаптивного
     IDLE + Active Poll (400 мс в окне 5 сек после трафика).
  6. Опциональный режим --ab-test: автоматический прогон Фазы A (1 ящик, N=1)
     и Фазы B (все N ящиков, Active-Active Striping) с таблицей прироста скорости и RTT.
"""

import argparse
import asyncio
import base64
import email.utils
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

LOG_FILE = "imap_multi_soak.log"
STATS_FILE = "imap_multi_soak_stats.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8"),
    ],
)
logger = logging.getLogger("IMAP-STRIPE")


@dataclass
class MailboxAccount:
    index: int
    email: str
    cli_pass: str
    srv_pass: str


@dataclass
class PerMailboxMetrics:
    index: int
    email: str
    cli_tx_batches: int = 0
    cli_tx_bytes: int = 0
    cli_rx_batches: int = 0
    cli_rx_bytes: int = 0
    srv_rx_batches: int = 0
    srv_rx_bytes: int = 0
    srv_tx_batches: int = 0
    srv_tx_bytes: int = 0
    binding_frames_rx: int = 0
    append_latencies_ms: List[float] = field(default_factory=list)
    fetch_latencies_ms: List[float] = field(default_factory=list)
    expunge_batches_count: int = 0
    expunged_uids_count: int = 0
    blind_window_hits: int = 0
    throttled_events: int = 0
    overquota_events: int = 0
    reconnect_events: int = 0
    retry_requeued: int = 0
    literal_plus_supported: bool = False


def percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(len(sorted_vals) * p)))
    return sorted_vals[idx]


@dataclass
class MultiSoakStats:
    phase_label: str = "Active-Active Striping"
    num_mailboxes: int = 1
    start_time: float = field(default_factory=time.time)
    duration_secs: float = 180.0

    cli_tx_batches: int = 0
    cli_tx_bytes: int = 0
    srv_tx_batches: int = 0
    srv_tx_bytes: int = 0

    cli_rx_batches: int = 0
    cli_rx_bytes: int = 0
    srv_rx_batches: int = 0
    srv_rx_bytes: int = 0

    rtt_samples_ms: List[float] = field(default_factory=list)
    uplink_hol_wait_ms: List[float] = field(default_factory=list)
    downlink_hol_wait_ms: List[float] = field(default_factory=list)

    out_of_order_deliveries: int = 0
    max_seq_seen: int = 0

    uid_fetch_duplicate_hits: int = 0
    errors: List[str] = field(default_factory=list)
    mailboxes: Dict[int, PerMailboxMetrics] = field(default_factory=dict)
    end_time: Optional[float] = None

    def mark_finished(self):
        if self.end_time is None:
            self.end_time = time.time()

    def to_summary_dict(self) -> dict:
        now_or_end = self.end_time if self.end_time is not None else time.time()
        elapsed = max(0.1, now_or_end - self.start_time)
        rtt_s = sorted(self.rtt_samples_ms)
        up_wait_s = sorted(self.uplink_hol_wait_ms)
        dn_wait_s = sorted(self.downlink_hol_wait_ms)

        all_append = []
        all_fetch = []
        for m in self.mailboxes.values():
            all_append.extend(m.append_latencies_ms)
            all_fetch.extend(m.fetch_latencies_ms)
        app_s = sorted(all_append)
        fet_s = sorted(all_fetch)

        uplink_mbps = (self.cli_tx_bytes * 8) / (elapsed * 1_000_000)
        downlink_mbps = (self.cli_rx_bytes * 8) / (elapsed * 1_000_000)

        mb_breakdown = {}
        for idx, m in sorted(self.mailboxes.items()):
            m_app_s = sorted(m.append_latencies_ms)
            m_fet_s = sorted(m.fetch_latencies_ms)
            tx_share = (
                (m.cli_tx_batches / self.cli_tx_batches * 100.0)
                if self.cli_tx_batches > 0
                else 0.0
            )
            rx_share = (
                (m.cli_rx_batches / self.cli_rx_batches * 100.0)
                if self.cli_rx_batches > 0
                else 0.0
            )
            mb_breakdown[f"mailbox_{idx}_{m.email}"] = {
                "email": m.email,
                "literal_plus": m.literal_plus_supported,
                "cli_tx_batches": m.cli_tx_batches,
                "cli_tx_share_pct": round(tx_share, 1),
                "cli_rx_batches": m.cli_rx_batches,
                "cli_rx_share_pct": round(rx_share, 1),
                "append_p50_ms": round(percentile(m_app_s, 0.50), 1),
                "append_p95_ms": round(percentile(m_app_s, 0.95), 1),
                "fetch_p50_ms": round(percentile(m_fet_s, 0.50), 1),
                "expunge_batches": m.expunge_batches_count,
                "expunged_uids": m.expunged_uids_count,
                "blind_window_hits": m.blind_window_hits,
                "throttled_events": m.throttled_events,
                "overquota_events": m.overquota_events,
                "reconnect_events": m.reconnect_events,
                "retry_requeued": m.retry_requeued,
            }

        return {
            "phase": self.phase_label,
            "num_mailboxes": self.num_mailboxes,
            "elapsed_secs": round(elapsed, 2),
            "cli_tx_batches": self.cli_tx_batches,
            "cli_tx_mib": round(self.cli_tx_bytes / (1024 * 1024), 3),
            "uplink_mbps": round(uplink_mbps, 3),
            "cli_rx_batches": self.cli_rx_batches,
            "cli_rx_mib": round(self.cli_rx_bytes / (1024 * 1024), 3),
            "downlink_mbps": round(downlink_mbps, 3),
            "rtt_p50_ms": round(percentile(rtt_s, 0.50), 1),
            "rtt_p95_ms": round(percentile(rtt_s, 0.95), 1),
            "rtt_p99_ms": round(percentile(rtt_s, 0.99), 1),
            "rtt_samples": len(rtt_s),
            "append_p50_ms": round(percentile(app_s, 0.50), 1),
            "append_p95_ms": round(percentile(app_s, 0.95), 1),
            "fetch_p50_ms": round(percentile(fet_s, 0.50), 1),
            "uplink_hol_wait_p50_ms": round(percentile(up_wait_s, 0.50), 1),
            "uplink_hol_wait_p95_ms": round(percentile(up_wait_s, 0.95), 1),
            "downlink_hol_wait_p50_ms": round(percentile(dn_wait_s, 0.50), 1),
            "out_of_order_batches": self.out_of_order_deliveries,
            "uid_duplicate_hits": self.uid_fetch_duplicate_hits,
            "mailboxes": mb_breakdown,
            "errors_sample": self.errors[:10],
        }

    def format_report(self) -> str:
        d = self.to_summary_dict()
        lines = [
            "",
            "================================================================================",
            f"   ОТЧЕТ ТЕСТИРОВАНИЯ IMAP: {self.phase_label} (Ящиков в пуле: N={self.num_mailboxes})",
            "================================================================================",
            f"Время тестирования:             {d['elapsed_secs']:.1f} сек ({d['elapsed_secs'] / 60.0:.2f} мин)",
            f"Отправлено клиентом (Uplink):   {d['cli_tx_batches']} батчей ({d['cli_tx_mib']:.2f} МиБ | {d['uplink_mbps']:.3f} Mbps)",
            f"Принято сервером (Uplink):      {self.srv_rx_batches} батчей ({self.srv_rx_bytes / (1024 * 1024):.2f} МиБ)",
            f"Отправлено сервером (Downlink): {self.srv_tx_batches} батчей ({self.srv_tx_bytes / (1024 * 1024):.2f} МиБ)",
            f"Принято клиентом (Downlink):    {d['cli_rx_batches']} батчей ({d['cli_rx_mib']:.2f} МиБ | {d['downlink_mbps']:.3f} Mbps)",
            f"Потери батчей (после дочитки):  {max(0, self.cli_tx_batches - self.srv_rx_batches)} Uplink, {max(0, self.srv_tx_batches - self.cli_rx_batches)} Downlink",
            "",
            "ЗАДЕРЖКИ DATA PLANE & SELF-CLOCKING DISPATCHER:",
            f"- End-to-End RTT (Клиент -> Сервер -> Клиент): p50={d['rtt_p50_ms']:.1f} мс | p95={d['rtt_p95_ms']:.1f} мс | p99={d['rtt_p99_ms']:.1f} мс (замеров: {d['rtt_samples']})",
            f"- Ожидание свободного воркера (Uplink HoL):    p50={d['uplink_hol_wait_p50_ms']:.1f} мс | p95={d['uplink_hol_wait_p95_ms']:.1f} мс",
            f"- Ожидание свободного воркера (Downlink HoL):  p50={d['downlink_hol_wait_p50_ms']:.1f} мс",
            f"- Задержка команды APPEND (по всем ящикам):    p50={d['append_p50_ms']:.1f} мс | p95={d['append_p95_ms']:.1f} мс",
            f"- Задержка команды UID FETCH (по всем ящикам): p50={d['fetch_p50_ms']:.1f} мс",
            f"- Внепорядковых приходов батчей (Out-of-Order):{self.out_of_order_deliveries} из {self.cli_rx_batches} (штатно для Striping)",
            "",
            "РАСПРЕДЕЛЕНИЕ НАГРУЗКИ ПО ЯЩИКАМ (ROUND-ROBIN / SELF-CLOCKING STRIPING):",
        ]
        for idx, m in sorted(self.mailboxes.items()):
            m_app_s = sorted(m.append_latencies_ms)
            m_fet_s = sorted(m.fetch_latencies_ms)
            tx_share = (
                (m.cli_tx_batches / self.cli_tx_batches * 100.0)
                if self.cli_tx_batches > 0
                else 0.0
            )
            rx_share = (
                (m.cli_rx_batches / self.cli_rx_batches * 100.0)
                if self.cli_rx_batches > 0
                else 0.0
            )
            lines.append(
                f"  [Ящик #{idx}: {m.email}] (LITERAL+: {'ДА' if m.literal_plus_supported else 'НЕТ'})\n"
                f"    Uplink TX:   {m.cli_tx_batches:4d} батчей ({tx_share:5.1f}%) | Downlink RX: {m.cli_rx_batches:4d} батчей ({rx_share:5.1f}%)\n"
                f"    APPEND RTT:  p50={percentile(m_app_s, 0.50):.1f} мс, p95={percentile(m_app_s, 0.95):.1f} мс | "
                f"FETCH RTT: p50={percentile(m_fet_s, 0.50):.1f} мс\n"
                f"    LazyExpunge: {m.expunge_batches_count} пачек ({m.expunged_uids_count} писем) | "
                f"BlindWin: {m.blind_window_hits} | Throttled: {m.throttled_events} | Retries: {m.retry_requeued}"
            )
        lines.append("================================================================================")
        return "\n".join(lines)


class RobustImapClient:
    """
    Асинхронный IMAPS-клиент с поддержкой:
      - Автоопределения LITERAL+ / LITERAL- по CAPABILITY (1-RTT APPEND);
      - Адаптивного IDLE с мгновенным выходом по '* N EXISTS';
      - Прямого бинарного чтения литералов через readexactly(msg_len);
      - Пакетного удаления прочитанных писем (UID STORE + UID EXPUNGE).
    """

    def __init__(
        self,
        host: str,
        port: int,
        email_addr: str,
        password: str,
        label: str,
        mb_metrics: PerMailboxMetrics,
        global_stats: MultiSoakStats,
        use_literal_plus: bool = True,
    ):
        self.host = host
        self.port = port
        self.email_addr = email_addr
        self.password = password
        self.label = label
        self.mb_metrics = mb_metrics
        self.stats = global_stats
        self.use_literal_plus = use_literal_plus

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.tag_counter = 0
        self.pending_exists = False
        self.in_idle = False
        self.idle_tag = ""
        self.literal_plus = False
        self.literal_minus = False
        self.logger = logging.getLogger(f"IMAP:{label}")

    def next_tag(self) -> str:
        self.tag_counter += 1
        return f"A{self.tag_counter:04d}"

    async def connect(self):
        ssl_ctx = ssl.create_default_context()
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=ssl_ctx
        )
        banner = await self.readline()
        self._parse_capabilities(banner)

        tag = self.next_tag()
        await self.send_line(f'{tag} LOGIN "{self.email_addr}" "{self.password}"')
        resp = await self.read_until_tagged(tag)
        if not resp[-1].startswith(f"{tag} OK"):
            raise RuntimeError(f"Login failed for {self.email_addr}: {resp[-1].strip()}")
        for line in resp:
            self._parse_capabilities(line)

        if self.use_literal_plus and not (self.literal_plus or self.literal_minus):
            cap_tag = self.next_tag()
            await self.send_line(f"{cap_tag} CAPABILITY")
            cap_resp = await self.read_until_tagged(cap_tag)
            for line in cap_resp:
                self._parse_capabilities(line)

        self.mb_metrics.literal_plus_supported = self.literal_plus or self.literal_minus
        self.logger.info(
            f"Connected as {self.email_addr} (LITERAL+: {self.literal_plus}, LITERAL-: {self.literal_minus})"
        )

    def _parse_capabilities(self, text: str):
        up = text.upper()
        if "LITERAL+" in up:
            self.literal_plus = True
        if "LITERAL-" in up:
            self.literal_minus = True

    async def send_line(self, line: str):
        self.writer.write(line.encode("utf-8") + b"\r\n")
        await self.writer.drain()

    async def readline(self) -> str:
        line_b = await self.reader.readline()
        if not line_b:
            raise ConnectionResetError("Connection closed by server")
        line = line_b.decode("latin1", errors="replace")

        if re.search(r"^\*\s+\d+\s+EXISTS", line, re.IGNORECASE):
            if not self.in_idle:
                self.mb_metrics.blind_window_hits += 1
            self.pending_exists = True

        return line

    async def read_until_tagged(self, tag: str, timeout_sec: float = 15.0) -> List[str]:
        lines = []
        start = time.time()
        while True:
            if time.time() - start > timeout_sec:
                raise asyncio.TimeoutError(f"Timeout waiting for tagged response {tag}")
            line = await asyncio.wait_for(self.readline(), timeout=timeout_sec)
            lines.append(line)
            if (
                line.startswith(f"{tag} OK")
                or line.startswith(f"{tag} NO")
                or line.startswith(f"{tag} BAD")
            ):
                break
        return lines

    async def create_folder(self, folder: str):
        tag = self.next_tag()
        await self.send_line(f'{tag} CREATE "{folder}"')
        resp = await self.read_until_tagged(tag)
        if resp[-1].startswith(f"{tag} OK"):
            self.logger.info(f"Created folder '{folder}' on {self.email_addr}")
        else:
            self.logger.debug(f"CREATE '{folder}' response on {self.email_addr}: {resp[-1].strip()}")

    async def select(self, folder: str):
        tag = self.next_tag()
        await self.send_line(f'{tag} SELECT "{folder}"')
        resp = await self.read_until_tagged(tag)
        if not resp[-1].startswith(f"{tag} OK"):
            self.logger.warning(
                f"SELECT '{folder}' returned '{resp[-1].strip()}' on {self.email_addr} "
                f"(new mailbox without '{folder}' folder) -> sending CREATE \"{folder}\"..."
            )
            await self.create_folder(folder)
            tag2 = self.next_tag()
            await self.send_line(f'{tag2} SELECT "{folder}"')
            resp2 = await self.read_until_tagged(tag2)
            if not resp2[-1].startswith(f"{tag2} OK"):
                raise RuntimeError(
                    f"SELECT {folder} failed after CREATE on {self.email_addr}: {resp2[-1].strip()}"
                )
        # Сбрасываем статический EXISTS от начального SELECT
        self.pending_exists = False

    async def append_message(
        self, folder: str, subject: str, payload_bytes: bytes, _retried_create: bool = False
    ) -> float:
        t0 = time.time()
        b64_content = base64.b64encode(payload_bytes).decode("ascii")
        b64_chunked = "\r\n".join(
            b64_content[i : i + 76] for i in range(0, len(b64_content), 76)
        )

        date_hdr = email.utils.formatdate(localtime=True)
        msg_raw = (
            f"From: <{self.email_addr}>\r\n"
            f"To: <{self.email_addr}>\r\n"
            f"Subject: {subject}\r\n"
            f"Date: {date_hdr}\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
            f"{b64_chunked}\r\n"
        ).encode("utf-8")

        tag = self.next_tag()
        can_non_sync = self.use_literal_plus and (
            self.literal_plus or (self.literal_minus and len(msg_raw) <= 4096)
        )

        if can_non_sync:
            cmd_head = f'{tag} APPEND "{folder}" (\\Seen \\Draft) {{{len(msg_raw)}+}}\r\n'.encode(
                "utf-8"
            )
            self.writer.write(cmd_head + msg_raw + b"\r\n")
            await self.writer.drain()
        else:
            await self.send_line(
                f'{tag} APPEND "{folder}" (\\Seen \\Draft) {{{len(msg_raw)}}}'
            )
            while True:
                line = await self.readline()
                if line.startswith("+"):
                    break
                if line.startswith(f"{tag} NO") or line.startswith(f"{tag} BAD"):
                    self._check_throttle(line)
                    if (
                        not _retried_create
                        and line.startswith(f"{tag} NO")
                        and "THROTTLED" not in line.upper()
                        and "OVERQUOTA" not in line.upper()
                    ):
                        self.logger.warning(
                            f"APPEND step 1 to '{folder}' returned '{line.strip()}', creating folder '{folder}' and retrying..."
                        )
                        await self.create_folder(folder)
                        return await self.append_message(
                            folder, subject, payload_bytes, _retried_create=True
                        )
                    raise RuntimeError(f"APPEND step 1 rejected: {line.strip()}")
            self.writer.write(msg_raw + b"\r\n")
            await self.writer.drain()

        resp = await self.read_until_tagged(tag)
        t_append = (time.time() - t0) * 1000.0
        self.mb_metrics.append_latencies_ms.append(t_append)

        if not resp[-1].startswith(f"{tag} OK"):
            self._check_throttle(resp[-1])
            if (
                not _retried_create
                and resp[-1].startswith(f"{tag} NO")
                and "THROTTLED" not in resp[-1].upper()
                and "OVERQUOTA" not in resp[-1].upper()
            ):
                self.logger.warning(
                    f"APPEND step 2 to '{folder}' returned '{resp[-1].strip()}', creating folder '{folder}' and retrying..."
                )
                await self.create_folder(folder)
                return await self.append_message(
                    folder, subject, payload_bytes, _retried_create=True
                )
            raise RuntimeError(f"APPEND failed: {resp[-1].strip()}")

        return t_append

    def _check_throttle(self, line: str):
        up = line.upper()
        if "THROTTLED" in up:
            self.mb_metrics.throttled_events += 1
        if "OVERQUOTA" in up:
            self.mb_metrics.overquota_events += 1

    async def enter_idle(self):
        tag = self.next_tag()
        self.idle_tag = tag
        await self.send_line(f"{tag} IDLE")
        while True:
            line = await self.readline()
            if line.startswith("+"):
                self.in_idle = True
                break
            if line.startswith(f"{tag} NO") or line.startswith(f"{tag} BAD"):
                raise RuntimeError(f"IDLE rejected: {line.strip()}")

    async def exit_idle(self):
        if not self.in_idle:
            return
        try:
            await self.send_line("DONE")
            await self.read_until_tagged(self.idle_tag, timeout_sec=5.0)
        except asyncio.TimeoutError:
            self.logger.warning("Timeout waiting for IDLE tagged response after DONE")
        finally:
            self.in_idle = False

    async def get_max_uid(self) -> int:
        tag = self.next_tag()
        await self.send_line(f"{tag} UID FETCH * (UID)")
        resp = await self.read_until_tagged(tag)
        max_uid = 0
        for line in resp:
            m = re.search(r"UID\s+(\d+)", line, re.IGNORECASE)
            if m:
                max_uid = max(max_uid, int(m.group(1)))
        return max_uid

    async def wait_idle_or_event(self, timeout_sec: float = 0.4) -> bool:
        await self.enter_idle()
        got_event = False
        t_start = time.time()
        try:
            while self.in_idle:
                remaining = timeout_sec - (time.time() - t_start)
                if remaining <= 0:
                    break
                try:
                    line = await asyncio.wait_for(self.readline(), timeout=remaining)
                    if re.search(r"^\*\s+\d+\s+EXISTS", line, re.IGNORECASE):
                        got_event = True
                        break
                except asyncio.TimeoutError:
                    break
        finally:
            await self.exit_idle()
        return got_event

    async def fetch_messages_robust(
        self, last_uid: int
    ) -> Tuple[List[Tuple[int, str, bytes]], int, float]:
        t0 = time.time()
        tag = self.next_tag()
        start_uid = last_uid + 1
        await self.send_line(f"{tag} UID FETCH {start_uid}:* (UID BODY.PEEK[])")

        messages = []
        new_max_uid = last_uid

        while True:
            line = await self.readline()
            if (
                line.startswith(f"{tag} OK")
                or line.startswith(f"{tag} NO")
                or line.startswith(f"{tag} BAD")
            ):
                break

            lit_m = re.search(r"\{(\d+)\}", line)
            if not lit_m:
                continue

            msg_len = int(lit_m.group(1))
            msg_bytes = await self.reader.readexactly(msg_len)
            rest_line = await self.readline()

            full_meta = line + " " + rest_line
            uid_m = re.search(r"UID\s+(\d+)", full_meta, re.IGNORECASE)
            if not uid_m:
                continue

            uid = int(uid_m.group(1))
            if uid <= last_uid:
                self.stats.uid_fetch_duplicate_hits += 1
                continue

            new_max_uid = max(new_max_uid, uid)

            try:
                split_idx = msg_bytes.find(b"\r\n\r\n")
                if split_idx != -1:
                    hdr_raw = msg_bytes[:split_idx].decode("latin1", errors="replace")
                    body_raw = msg_bytes[split_idx + 4 :]
                else:
                    split_idx = msg_bytes.find(b"\n\n")
                    hdr_raw = msg_bytes[:split_idx].decode("latin1", errors="replace")
                    body_raw = msg_bytes[split_idx + 2 :]

                subject = ""
                for h in hdr_raw.splitlines():
                    if h.lower().startswith("subject:"):
                        subject = h.split(":", 1)[1].strip()
                        break

                clean_b64 = body_raw.replace(b"\r", b"").replace(b"\n", b"").strip()
                payload = base64.b64decode(clean_b64) if clean_b64 else b""
                messages.append((uid, subject, payload))

            except Exception as e:
                self.stats.errors.append(f"UID {uid}: {e}")
                self.logger.error(f"Failed to extract payload UID {uid}: {e}")

        t_fetch = (time.time() - t0) * 1000.0
        self.mb_metrics.fetch_latencies_ms.append(t_fetch)
        return messages, new_max_uid, t_fetch

    async def expunge_uids(self, uids: List[int]):
        if not uids:
            return
        uid_str = ",".join(str(u) for u in uids)
        tag1 = self.next_tag()
        await self.send_line(f"{tag1} UID STORE {uid_str} +FLAGS.SILENT (\\Deleted)")
        await self.read_until_tagged(tag1)

        tag2 = self.next_tag()
        await self.send_line(f"{tag2} UID EXPUNGE {uid_str}")
        resp = await self.read_until_tagged(tag2)
        if not resp[-1].startswith(f"{tag2} OK"):
            tag3 = self.next_tag()
            await self.send_line(f"{tag3} EXPUNGE")
            await self.read_until_tagged(tag3)

        self.mb_metrics.expunge_batches_count += 1
        self.mb_metrics.expunged_uids_count += len(uids)

    async def close(self):
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass


# =========================================================================
# Архитектура Раздела 9: Слоты воркеров и центральные Self-Clocking диспетчеры
# =========================================================================


class MailboxWorkerSlot:
    """
    Представляет выделенный слот отправки для одного ящика (CLI_WRITER[i] или SRV_WRITER[i]).
    Эмулирует канал ёмкостью 1 (`mpsc::channel(1)` + `try_reserve_owned()` / `reserve_owned()`)
    из Раздела 9.4.2 / 9.5.3:
      - `idle_event` установлен, когда воркер свободен и готов мгновенно принять батч;
      - когда диспетчер резервирует слот (`try_reserve` или ожидание `idle_event`),
        `idle_event` сбрасывается до завершения сетевого `APPEND`.
    """

    def __init__(self, index: int, account: MailboxAccount):
        self.index = index
        self.account = account
        self.healthy: bool = False
        self.idle_event: asyncio.Event = asyncio.Event()
        self.batch_queue: asyncio.Queue[Tuple[str, bytes, bool]] = asyncio.Queue(maxsize=1)

    def is_available(self) -> bool:
        return self.healthy and self.idle_event.is_set() and self.batch_queue.empty()

    def dispatch_nowait(self, subject: str, payload: bytes, is_binding: bool = False):
        self.idle_event.clear()
        self.batch_queue.put_nowait((subject, payload, is_binding))


class SessionMailboxPool:
    """
    Серверный динамический пул активных ящиков клиентской сессии (Раздел 9.5.2).
    Ящик попадает в пул, как только SRV_READER[i] получает первый валидный пакет
    или Mailbox Binding Frame с `[ID: srv01:<session_id>]`.
    """

    def __init__(self):
        self.active_indices: Set[int] = set()
        self.rr_cursor: int = 0
        self.pool_updated: asyncio.Event = asyncio.Event()

    def register_mailbox(self, mailbox_idx: int, email_addr: str):
        if mailbox_idx not in self.active_indices:
            self.active_indices.add(mailbox_idx)
            self.pool_updated.set()
            logger.info(
                f"[SRV-POOL] Mailbox #{mailbox_idx} ({email_addr}) dynamically bound to session pool! "
                f"Active downlink mailboxes: {sorted(self.active_indices)}"
            )


async def select_slot_self_clocking(
    slots: List[MailboxWorkerSlot],
    allowed_indices: Optional[Set[int]],
    rr_cursor: int,
    stop_event: asyncio.Event,
) -> Tuple[Optional[MailboxWorkerSlot], int, float]:
    """
    Универсальная реализация алгоритма Self-Clocking Round-Robin (Раздел 9.4.2 & 9.5.3):
      1. Fast Path: неблокирующий обход здоровых слотов от `rr_cursor`.
      2. All-Busy Path: если все здоровые воркеры сейчас заняты выполнением `APPEND`,
         асинхронно ждёт ПЕРВОГО освободившегося воркера (`FIRST_COMPLETED`).
    Возвращает: (выбранный_слот, новый_rr_cursor, время_ожидания_в_мс).
    """
    t0 = time.time()
    n = len(slots)

    while not stop_event.is_set():
        # Фаза 1: Мгновенный неблокирующий Round-Robin (Fast Path)
        for offset in range(n):
            idx = (rr_cursor + offset) % n
            if allowed_indices is not None and idx not in allowed_indices:
                continue
            slot = slots[idx]
            if slot.is_available():
                wait_ms = (time.time() - t0) * 1000.0
                return slot, (idx + 1) % n, wait_ms

        # Фаза 2: Все ящики заняты APPEND — ждём первого освободившегося (All-Busy Path)
        candidates = [
            slots[(rr_cursor + offset) % n]
            for offset in range(n)
            if slots[(rr_cursor + offset) % n].healthy
            and (allowed_indices is None or ((rr_cursor + offset) % n) in allowed_indices)
        ]
        if not candidates:
            await asyncio.sleep(0.02)
            continue

        wait_tasks = [
            asyncio.create_task(s.idle_event.wait(), name=f"slot_{s.index}")
            for s in candidates
        ]
        stop_task = asyncio.create_task(stop_event.wait(), name="stop")
        done, pending = await asyncio.wait(
            wait_tasks + [stop_task],
            timeout=0.1,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for p in pending:
            p.cancel()

    return None, rr_cursor, (time.time() - t0) * 1000.0


async def run_server_mailbox_worker(
    account: MailboxAccount,
    host: str,
    port: int,
    slot: MailboxWorkerSlot,
    session_pool: SessionMailboxPool,
    downlink_echo_queue: asyncio.Queue,
    stats: MultiSoakStats,
    stop_event: asyncio.Event,
    use_literal_plus: bool,
    expunge_batch_size: int = 25,
    expunge_idle_delay_sec: float = 1.5,
):
    """
    Серверная пара воркеров (SRV_READER[i] + SRV_WRITER[i]) для одного ящика `account.index`.
    Строго изолирует `last_seen_uid` и `cleanup_uids` папки "Drafts" внутри своего ящика.
    """
    idx = account.index
    mb_metrics = stats.mailboxes[idx]

    while not stop_event.is_set():
        srv_reader = RobustImapClient(
            host, port, account.email, account.srv_pass, f"SRV_R#{idx}", mb_metrics, stats, use_literal_plus
        )
        srv_writer = RobustImapClient(
            host, port, account.email, account.srv_pass, f"SRV_W#{idx}", mb_metrics, stats, use_literal_plus
        )
        writer_task: Optional[asyncio.Task] = None
        cleanup_uids: List[int] = []

        try:
            await srv_reader.connect()
            await srv_reader.select("Drafts")

            await srv_writer.connect()
            # Гарантируем наличие обеих папок ("Notes" и "Drafts") на свежезарегистрированных ящиках
            await srv_writer.select("Notes")
            await srv_writer.select("Drafts")

            last_seen_uid = await srv_reader.get_max_uid()
            srv_reader.logger.info(f"[Mailbox #{idx}] Initial 'Drafts' baseline UID: {last_seen_uid}")

            last_rx_time = time.time()

            slot.healthy = True
            slot.idle_event.set()

            async def srv_writer_loop():
                while not stop_event.is_set():
                    try:
                        # Проверяем, нужно ли выполнить ленивый пакетный EXPUNGE прочитанных писем в "Drafts"
                        should_expunge = len(cleanup_uids) >= expunge_batch_size or (
                            len(cleanup_uids) > 0 and (time.time() - last_rx_time) >= expunge_idle_delay_sec
                        )
                        if should_expunge and slot.batch_queue.empty():
                            slot.idle_event.clear()
                            to_clean = cleanup_uids[:]
                            cleanup_uids.clear()
                            await srv_writer.expunge_uids(to_clean)
                            slot.idle_event.set()

                        try:
                            subj, payload, _ = await asyncio.wait_for(
                                slot.batch_queue.get(), timeout=0.05
                            )
                        except asyncio.TimeoutError:
                            continue

                        try:
                            await srv_writer.append_message("Notes", subj, payload)
                            stats.srv_tx_batches += 1
                            stats.srv_tx_bytes += len(payload)
                            mb_metrics.srv_tx_batches += 1
                            mb_metrics.srv_tx_bytes += len(payload)

                            # Если накопился полный батч на очистку — чистим попутно после APPEND
                            if len(cleanup_uids) >= expunge_batch_size:
                                to_clean = cleanup_uids[:]
                                cleanup_uids.clear()
                                await srv_writer.expunge_uids(to_clean)
                        except Exception as e:
                            srv_writer.logger.error(
                                f"APPEND error on SRV_W#{idx}, re-queuing downlink batch: {e}"
                            )
                            stats.errors.append(f"SRV_W#{idx}: {e}")
                            mb_metrics.retry_requeued += 1
                            # Возвращаем батч в центральную очередь Downlink без потерь!
                            await downlink_echo_queue.put((subj, payload))
                            await asyncio.sleep(0.3)
                        finally:
                            slot.idle_event.set()

                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        srv_writer.logger.error(f"Unexpected SRV_W#{idx} loop error: {e}")
                        await asyncio.sleep(0.5)

            writer_task = asyncio.create_task(srv_writer_loop())
            last_activity_ts = time.time()

            while not stop_event.is_set():
                if not srv_reader.pending_exists:
                    in_active_window = (time.time() - last_activity_ts) < 5.0
                    idle_timeout = 0.4 if in_active_window else 10.0
                    got_evt = await srv_reader.wait_idle_or_event(timeout_sec=idle_timeout)
                    if stop_event.is_set():
                        break
                    if not got_evt and not srv_reader.pending_exists and not in_active_window:
                        continue

                srv_reader.pending_exists = False
                msgs, new_max, _ = await srv_reader.fetch_messages_robust(last_seen_uid)
                last_seen_uid = new_max

                if msgs:
                    last_activity_ts = time.time()
                    last_rx_time = last_activity_ts

                for uid, subject, payload in msgs:
                    cleanup_uids.append(uid)
                    id_match = re.search(r"\[ID:\s*([^\]]+)\]", subject)
                    if not id_match:
                        continue

                    # Любой валидный фрейм с [ID: srv01:<session_id>] регистрирует этот ящик в SessionMailboxPool!
                    session_pool.register_mailbox(idx, account.email)

                    if len(payload) == 0:
                        # Это управляющий Mailbox Binding Frame (Раздел 9.3.3)
                        mb_metrics.binding_frames_rx += 1
                        continue

                    stats.srv_rx_batches += 1
                    stats.srv_rx_bytes += len(payload)
                    mb_metrics.srv_rx_batches += 1
                    mb_metrics.srv_rx_bytes += len(payload)

                    cli_target = id_match.group(1).split(":")[-1]
                    echo_subj = f"[ID: {cli_target}]"
                    await downlink_echo_queue.put((echo_subj, payload))

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(
                f"[SRV Mailbox #{idx} ({account.email})] Worker error: {e}", exc_info=True
            )
            stats.errors.append(f"SRV#{idx} ({account.email}): {e}")
            mb_metrics.reconnect_events += 1
        finally:
            slot.healthy = False
            if writer_task is not None:
                writer_task.cancel()
            if cleanup_uids:
                try:
                    await srv_writer.expunge_uids(cleanup_uids)
                except Exception:
                    pass
            await srv_reader.close()
            await srv_writer.close()

        if not stop_event.is_set():
            await asyncio.sleep(2.0)


async def run_server_downlink_dispatcher(
    srv_slots: List[MailboxWorkerSlot],
    session_pool: SessionMailboxPool,
    downlink_echo_queue: asyncio.Queue,
    stats: MultiSoakStats,
    stop_event: asyncio.Event,
):
    """
    Центральный диспетчер Downlink на сервере (`run_client_downlink_batcher` из Раздела 9.5.3).
    Берёт ответные батчи из общей очереди сессии и распределяет их по всем привязанным ящикам
    в `session_pool.active_indices` по алгоритму Self-Clocking Round-Robin.
    """
    rr_cursor = 0
    while not stop_event.is_set():
        try:
            subj, payload = await asyncio.wait_for(downlink_echo_queue.get(), timeout=0.1)
        except asyncio.TimeoutError:
            continue

        while not session_pool.active_indices and not stop_event.is_set():
            await asyncio.sleep(0.01)

        slot, rr_cursor, wait_ms = await select_slot_self_clocking(
            srv_slots, session_pool.active_indices, rr_cursor, stop_event
        )
        if slot is None:
            break

        stats.downlink_hol_wait_ms.append(wait_ms)
        slot.dispatch_nowait(subj, payload)


async def run_client_mailbox_worker(
    account: MailboxAccount,
    host: str,
    port: int,
    slot: MailboxWorkerSlot,
    retry_uplink_queue: asyncio.Queue,
    sent_timestamps: Dict[int, float],
    stats: MultiSoakStats,
    stop_event: asyncio.Event,
    session_id: str,
    use_literal_plus: bool,
    expunge_batch_size: int = 25,
    expunge_idle_delay_sec: float = 1.5,
):
    """
    Клиентская пара воркеров (CLI_READER[i] + CLI_WRITER[i]) для одного ящика `account.index`.
    Строго изолирует `last_seen_uid` и `cleanup_uids` папки "Notes" своего ящика.
    """
    idx = account.index
    mb_metrics = stats.mailboxes[idx]

    while not stop_event.is_set():
        cli_reader = RobustImapClient(
            host, port, account.email, account.cli_pass, f"CLI_R#{idx}", mb_metrics, stats, use_literal_plus
        )
        cli_writer = RobustImapClient(
            host, port, account.email, account.cli_pass, f"CLI_W#{idx}", mb_metrics, stats, use_literal_plus
        )
        writer_task: Optional[asyncio.Task] = None
        cleanup_uids: List[int] = []

        try:
            await cli_reader.connect()
            await cli_reader.select("Notes")

            await cli_writer.connect()
            # Гарантируем наличие обеих папок ("Drafts" и "Notes") на свежезарегистрированных ящиках
            await cli_writer.select("Drafts")
            await cli_writer.select("Notes")

            last_seen_uid = await cli_reader.get_max_uid()
            cli_reader.logger.info(f"[Mailbox #{idx}] Initial 'Notes' baseline UID: {last_seen_uid}")

            # Отправляем Mailbox Binding Frame (Раздел 9.3.3), чтобы сервер сразу привязал ящик #idx к пулу сессии!
            binding_subj = f"ANet-Data [ID: srv01:{session_id}]"
            await cli_writer.append_message("Drafts", binding_subj, b"")
            cli_writer.logger.info(f"[Mailbox #{idx}] Sent Mailbox Binding Frame for session {session_id}")

            last_rx_time = time.time()

            slot.healthy = True
            slot.idle_event.set()

            async def cli_writer_loop():
                while not stop_event.is_set():
                    try:
                        should_expunge = len(cleanup_uids) >= expunge_batch_size or (
                            len(cleanup_uids) > 0 and (time.time() - last_rx_time) >= expunge_idle_delay_sec
                        )
                        if should_expunge and slot.batch_queue.empty():
                            slot.idle_event.clear()
                            to_clean = cleanup_uids[:]
                            cleanup_uids.clear()
                            await cli_writer.expunge_uids(to_clean)
                            slot.idle_event.set()

                        try:
                            subj, payload, _ = await asyncio.wait_for(
                                slot.batch_queue.get(), timeout=0.05
                            )
                        except asyncio.TimeoutError:
                            continue

                        try:
                            await cli_writer.append_message("Drafts", subj, payload)
                            stats.cli_tx_batches += 1
                            stats.cli_tx_bytes += len(payload)
                            mb_metrics.cli_tx_batches += 1
                            mb_metrics.cli_tx_bytes += len(payload)

                            if len(cleanup_uids) >= expunge_batch_size:
                                to_clean = cleanup_uids[:]
                                cleanup_uids.clear()
                                await cli_writer.expunge_uids(to_clean)
                        except Exception as e:
                            cli_writer.logger.error(
                                f"APPEND error on CLI_W#{idx}, returning batch to retry_uplink_queue: {e}"
                            )
                            stats.errors.append(f"CLI_W#{idx}: {e}")
                            mb_metrics.retry_requeued += 1
                            # Zero-Loss Retry (Раздел 9.4.3): возвращаем батч центральному диспетчеру!
                            await retry_uplink_queue.put((subj, payload))
                            await asyncio.sleep(0.3)
                        finally:
                            slot.idle_event.set()

                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        cli_writer.logger.error(f"Unexpected CLI_W#{idx} loop error: {e}")
                        await asyncio.sleep(0.5)

            writer_task = asyncio.create_task(cli_writer_loop())
            last_activity_ts = time.time()

            while not stop_event.is_set():
                if not cli_reader.pending_exists:
                    in_active_window = (time.time() - last_activity_ts) < 5.0
                    idle_timeout = 0.4 if in_active_window else 10.0
                    got_evt = await cli_reader.wait_idle_or_event(timeout_sec=idle_timeout)
                    if stop_event.is_set():
                        break
                    if not got_evt and not cli_reader.pending_exists and not in_active_window:
                        continue

                cli_reader.pending_exists = False
                msgs, new_max, _ = await cli_reader.fetch_messages_robust(last_seen_uid)
                last_seen_uid = new_max

                if msgs:
                    last_activity_ts = time.time()
                    last_rx_time = last_activity_ts

                for uid, subject, payload in msgs:
                    cleanup_uids.append(uid)
                    if not payload:
                        continue

                    stats.cli_rx_batches += 1
                    stats.cli_rx_bytes += len(payload)
                    mb_metrics.cli_rx_batches += 1
                    mb_metrics.cli_rx_bytes += len(payload)

                    if len(payload) >= 16:
                        seq = int.from_bytes(payload[0:8], "big")
                        if seq < stats.max_seq_seen:
                            stats.out_of_order_deliveries += 1
                        else:
                            stats.max_seq_seen = seq

                        if seq in sent_timestamps:
                            rtt = (time.time() - sent_timestamps.pop(seq)) * 1000.0
                            stats.rtt_samples_ms.append(rtt)
                            if stats.cli_rx_batches == 1 or stats.cli_rx_batches % 10 == 0:
                                elapsed = max(0.1, time.time() - stats.start_time)
                                cur_mbps = (stats.cli_rx_bytes * 8) / (elapsed * 1_000_000)
                                logger.info(
                                    f"[ECHO #{seq} via Box#{idx}] RTT: {rtt:.1f} ms | "
                                    f"Total RX: {stats.cli_rx_bytes / (1024 * 1024):.2f} MiB ({cur_mbps:.2f} Mbps) | "
                                    f"InFlight: {len(sent_timestamps)}"
                                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(
                f"[CLI Mailbox #{idx} ({account.email})] Worker error: {e}", exc_info=True
            )
            stats.errors.append(f"CLI#{idx} ({account.email}): {e}")
            mb_metrics.reconnect_events += 1
        finally:
            slot.healthy = False
            if writer_task is not None:
                writer_task.cancel()
            if cleanup_uids:
                try:
                    await cli_writer.expunge_uids(cleanup_uids)
                except Exception:
                    pass
            await cli_reader.close()
            await cli_writer.close()

        if not stop_event.is_set():
            await asyncio.sleep(2.0)


async def run_client_uplink_dispatcher(
    cli_slots: List[MailboxWorkerSlot],
    retry_uplink_queue: asyncio.Queue,
    sent_timestamps: Dict[int, float],
    stats: MultiSoakStats,
    stop_event: asyncio.Event,
    session_id: str,
    batch_kb: int,
    max_inflight_per_box: int = 12,
):
    """
    Центральный диспетчер Uplink на клиенте (`Self-Clocking Round-Robin Uplink Dispatcher`, Раздел 9.4.2).
    Держит единый генератор/коалесцер батчей и распределяет их по пулу из N здоровых ящиков.
    """
    seq_counter = 0
    rr_cursor = 0
    payload_padding = b"X" * max(64, batch_kb * 1024 - 64)
    max_total_inflight = max_inflight_per_box * len(cli_slots)

    # Ждём готовности хотя бы одного клиентского воркера
    while not any(s.healthy for s in cli_slots) and not stop_event.is_set():
        await asyncio.sleep(0.02)

    while not stop_event.is_set():
        # Контроль общего окна неподтверждённых батчей (Backpressure)
        if len(sent_timestamps) >= max_total_inflight and retry_uplink_queue.empty():
            await asyncio.sleep(0.02)
            continue

        # Сначала ждём освобождения первого доступного ящика (Self-Clocking Round-Robin)
        slot, rr_cursor, wait_ms = await select_slot_self_clocking(
            cli_slots, None, rr_cursor, stop_event
        )
        if slot is None:
            break

        stats.uplink_hol_wait_ms.append(wait_ms)

        # Приоритет №1: повторная отправка батча из retry_uplink_queue при сбое соседнего ящика
        if not retry_uplink_queue.empty():
            subj, payload = retry_uplink_queue.get_nowait()
            slot.dispatch_nowait(subj, payload)
            continue

        # Формируем новый батч с текущей меткой времени непосредственно перед передачей свободному воркеру!
        # (Как и в Разделе 9.4.2: пока все воркеры заняты, данные копятся и упаковываются в момент освобождения слота)
        seq_counter += 1
        now = time.time()
        header = seq_counter.to_bytes(8, "big") + int(now * 1_000_000).to_bytes(8, "big")
        payload = header + payload_padding
        sent_timestamps[seq_counter] = now

        subj = f"ANet-Data [ID: srv01:{session_id}]"
        slot.dispatch_nowait(subj, payload)


async def run_phase(
    phase_label: str,
    accounts: List[MailboxAccount],
    host: str,
    port: int,
    duration_secs: float,
    batch_kb: int,
    use_literal_plus: bool,
) -> MultiSoakStats:
    stats = MultiSoakStats(
        phase_label=phase_label,
        num_mailboxes=len(accounts),
        start_time=time.time(),
        duration_secs=duration_secs,
    )
    for acc in accounts:
        stats.mailboxes[acc.index] = PerMailboxMetrics(index=acc.index, email=acc.email)

    stop_event = asyncio.Event()
    session_id = f"stripe_{int(time.time()):x}"
    session_pool = SessionMailboxPool()
    downlink_echo_queue: asyncio.Queue = asyncio.Queue()
    retry_uplink_queue: asyncio.Queue = asyncio.Queue()
    sent_timestamps: Dict[int, float] = {}

    srv_slots = [MailboxWorkerSlot(acc.index, acc) for acc in accounts]
    cli_slots = [MailboxWorkerSlot(acc.index, acc) for acc in accounts]

    logger.info(
        f"=== ЗАПУСК ФАЗЫ '{phase_label}' | Ящиков: N={len(accounts)} | "
        f"Длительность: {duration_secs:.0f} сек | Батч: {batch_kb} КБ ==="
    )

    tasks = []
    # 1. Запускаем N пар серверных воркеров (SRV_READER[i] + SRV_WRITER[i])
    for i, acc in enumerate(accounts):
        tasks.append(
            asyncio.create_task(
                run_server_mailbox_worker(
                    acc,
                    host,
                    port,
                    srv_slots[i],
                    session_pool,
                    downlink_echo_queue,
                    stats,
                    stop_event,
                    use_literal_plus,
                )
            )
        )

    # Небольшая пауза, чтобы серверные воркеры успели зайти в SELECT "Drafts" до отправки Binding Frame
    await asyncio.sleep(1.5)

    # 2. Запускаем центральный серверный диспетчер Downlink
    tasks.append(
        asyncio.create_task(
            run_server_downlink_dispatcher(
                srv_slots, session_pool, downlink_echo_queue, stats, stop_event
            )
        )
    )

    # 3. Запускаем N пар клиентских воркеров (CLI_READER[i] + CLI_WRITER[i])
    for i, acc in enumerate(accounts):
        tasks.append(
            asyncio.create_task(
                run_client_mailbox_worker(
                    acc,
                    host,
                    port,
                    cli_slots[i],
                    retry_uplink_queue,
                    sent_timestamps,
                    stats,
                    stop_event,
                    session_id,
                    use_literal_plus,
                )
            )
        )

    # 4. Запускаем центральный клиентский диспетчер Uplink (Self-Clocking Round-Robin)
    tasks.append(
        asyncio.create_task(
            run_client_uplink_dispatcher(
                cli_slots,
                retry_uplink_queue,
                sent_timestamps,
                stats,
                stop_event,
                session_id,
                batch_kb,
            )
        )
    )

    async def progress_reporter():
        while not stop_event.is_set():
            await asyncio.sleep(15.0)
            elapsed = max(0.1, time.time() - stats.start_time)
            tx_mbps = (stats.cli_tx_bytes * 8) / (elapsed * 1_000_000)
            rx_mbps = (stats.cli_rx_bytes * 8) / (elapsed * 1_000_000)
            shares = " | ".join(
                f"Box#{idx}: TX={m.cli_tx_batches}/RX={m.cli_rx_batches}"
                for idx, m in sorted(stats.mailboxes.items())
            )
            logger.info(
                f"[{phase_label} N={len(accounts)}] {elapsed:.0f}/{duration_secs:.0f}s | "
                f"Uplink: {stats.cli_tx_bytes / (1024 * 1024):.2f} MiB ({tx_mbps:.2f} Mbps) | "
                f"Downlink: {stats.cli_rx_bytes / (1024 * 1024):.2f} MiB ({rx_mbps:.2f} Mbps) | "
                f"{shares}"
            )

    reporter_task = asyncio.create_task(progress_reporter())

    try:
        await asyncio.sleep(duration_secs)
    except asyncio.CancelledError:
        pass
    finally:
        stop_event.set()
        reporter_task.cancel()
        await asyncio.sleep(1.5)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        stats.mark_finished()

    logger.info(stats.format_report())
    return stats


def parse_accounts_from_args(args: argparse.Namespace) -> Tuple[str, int, List[MailboxAccount]]:
    host = args.host
    port = args.port
    raw_accounts: List[Tuple[str, str, str]] = []

    # 1. Разбор из --dsn "imap://imap.mail.ru:993?acc=u1:p1&acc=u2:p2"
    if args.dsn:
        parsed = urllib.parse.urlparse(args.dsn)
        if parsed.hostname:
            host = parsed.hostname
        if parsed.port:
            port = parsed.port
        qs = urllib.parse.parse_qs(parsed.query)
        for acc_val in qs.get("acc", []):
            parts = acc_val.split(":")
            if len(parts) == 2:
                raw_accounts.append((parts[0], parts[1], parts[1]))
            elif len(parts) >= 3:
                raw_accounts.append((parts[0], parts[1], parts[2]))

    # 2. Разбор из повторяющихся флагов --acc "email:pass" или "email:cli_pass:srv_pass"
    if args.acc:
        for acc_val in args.acc:
            parts = acc_val.split(":")
            if len(parts) == 2:
                raw_accounts.append((parts[0], parts[1], parts[1]))
            elif len(parts) >= 3:
                raw_accounts.append((parts[0], parts[1], parts[2]))

    # 3. Совместимость с одиночными флагами imap_soak_test.py (--email, --cli-pass, --srv-pass)
    if args.email:
        c_pass = args.cli_pass or args.srv_pass
        s_pass = args.srv_pass or args.cli_pass
        if not c_pass:
            raise ValueError("Для --email необходимо указать --cli-pass (и опционально --srv-pass)")
        raw_accounts.append((args.email, c_pass, s_pass))

    # 4. Удобные флаги для второго ящика (--email2, --pass2 / --cli-pass2 / --srv-pass2)
    if args.email2:
        c_pass2 = args.cli_pass2 or args.pass2 or args.srv_pass2
        s_pass2 = args.srv_pass2 or args.pass2 or args.cli_pass2
        if not c_pass2:
            raise ValueError("Для --email2 необходимо указать --pass2 или --cli-pass2")
        raw_accounts.append((args.email2, c_pass2, s_pass2))

    if not raw_accounts:
        raise ValueError(
            "Не указано ни одного ящика! Используйте:\n"
            '  --acc "box1@mail.ru:pass1" --acc "box2@mail.ru:pass2"\n'
            "  или --dsn \"imap://imap.mail.ru:993?acc=box1@mail.ru:pass1&acc=box2@mail.ru:pass2\"\n"
            "  или --email box1@mail.ru --cli-pass pass1 --email2 box2@mail.ru --pass2 pass2"
        )

    accounts = [
        MailboxAccount(index=i, email=e, cli_pass=cp, srv_pass=sp)
        for i, (e, cp, sp) in enumerate(raw_accounts)
    ]
    return host, port, accounts


def print_ab_comparison(stats_single: MultiSoakStats, stats_multi: MultiSoakStats):
    d1 = stats_single.to_summary_dict()
    dn = stats_multi.to_summary_dict()

    up_gain = (dn["uplink_mbps"] / d1["uplink_mbps"]) if d1["uplink_mbps"] > 0 else 0.0
    dn_gain = (dn["downlink_mbps"] / d1["downlink_mbps"]) if d1["downlink_mbps"] > 0 else 0.0
    rtt_diff = dn["rtt_p50_ms"] - d1["rtt_p50_ms"]

    table = f"""
################################################################################
      СРАВНИТЕЛЬНЫЙ ОТЧЕТ A/B: 1 ЯЩИК (N=1) vs ПУЛ ЯЩИКОВ (N={stats_multi.num_mailboxes})
################################################################################
Метрика                          | N=1 (Одиночный)   | N={stats_multi.num_mailboxes} (Active-Active) | Эффект / Прирост
---------------------------------+-------------------+---------------------+--------------------
Скорость Uplink (Mbps)           | {d1['uplink_mbps']:>12.3f} Mbps | {dn['uplink_mbps']:>14.3f} Mbps | x{up_gain:.2f} ({(up_gain - 1) * 100:+.1f}%)
Скорость Downlink (Mbps)         | {d1['downlink_mbps']:>12.3f} Mbps | {dn['downlink_mbps']:>14.3f} Mbps | x{dn_gain:.2f} ({(dn_gain - 1) * 100:+.1f}%)
Прокачано батчей (Uplink)        | {d1['cli_tx_batches']:>17d} | {dn['cli_tx_batches']:>19d} | +{dn['cli_tx_batches'] - d1['cli_tx_batches']} батчей
End-to-End RTT p50 (мс)          | {d1['rtt_p50_ms']:>14.1f} мс | {dn['rtt_p50_ms']:>16.1f} мс | {rtt_diff:+.1f} мс
End-to-End RTT p95 (мс)          | {d1['rtt_p95_ms']:>14.1f} мс | {dn['rtt_p95_ms']:>16.1f} мс | {dn['rtt_p95_ms'] - d1['rtt_p95_ms']:+.1f} мс
Ожидание слота Uplink HoL p50    | {d1['uplink_hol_wait_p50_ms']:>14.1f} мс | {dn['uplink_hol_wait_p50_ms']:>16.1f} мс | {dn['uplink_hol_wait_p50_ms'] - d1['uplink_hol_wait_p50_ms']:+.1f} мс
################################################################################
"""
    logger.info(table)


async def main():
    parser = argparse.ArgumentParser(
        description="ANet IMAP Active-Active Multi-Mailbox Round-Robin / Striping Soak Test"
    )
    parser.add_argument(
        "--dsn",
        default=os.getenv("ANET_IMAP_DSN"),
        help='Полный IMAP DSN, например: "imap://imap.mail.ru:993?acc=u1@mail.ru:p1&acc=u2@mail.ru:p2"',
    )
    parser.add_argument(
        "--acc",
        action="append",
        help='Аккаунт в формате "email:app_password" или "email:cli_pass:srv_pass" (можно указывать несколько раз)',
    )
    parser.add_argument("--email", default=os.getenv("ANET_IMAP_EMAIL"), help="Email ящика #1")
    parser.add_argument("--cli-pass", default=os.getenv("ANET_IMAP_CLI_PASS"), help="Пароль клиента для ящика #1")
    parser.add_argument("--srv-pass", default=os.getenv("ANET_IMAP_SRV_PASS"), help="Пароль сервера для ящика #1")
    parser.add_argument("--email2", default=os.getenv("ANET_IMAP_EMAIL2"), help="Email ящика #2")
    parser.add_argument("--pass2", default=os.getenv("ANET_IMAP_PASS2"), help="Пароль приложения для ящика #2")
    parser.add_argument("--cli-pass2", default=os.getenv("ANET_IMAP_CLI_PASS2"), help="Пароль клиента для ящика #2")
    parser.add_argument("--srv-pass2", default=os.getenv("ANET_IMAP_SRV_PASS2"), help="Пароль сервера для ящика #2")
    parser.add_argument("--host", default="imap.mail.ru", help="IMAP сервер (по умолчанию: imap.mail.ru)")
    parser.add_argument("--port", type=int, default=993, help="IMAP порт (по умолчанию: 993)")
    parser.add_argument(
        "--duration-mins",
        type=float,
        default=3.0,
        help="Длительность одной фазы теста в минутах (по умолчанию: 3)",
    )
    parser.add_argument(
        "--batch-kb",
        type=int,
        default=96,
        help="Размер полезной нагрузки одного батча в КБ (по умолчанию: 96 КБ, как в оптимизированном профиле)",
    )
    parser.add_argument(
        "--no-literal-plus",
        action="store_true",
        help="Принудительно отключить 1-RTT LITERAL+ (использовать классический 2-шаговый APPEND)",
    )
    parser.add_argument(
        "--ab-test",
        action="store_true",
        help="Автоматически провести A/B сравнение: сначала прогон на 1 ящике (N=1), затем на всех N ящиках (Active-Active Striping)",
    )
    args = parser.parse_args()

    try:
        host, port, accounts = parse_accounts_from_args(args)
    except ValueError as e:
        parser.error(str(e))
        return

    duration_secs = max(15.0, args.duration_mins * 60.0)
    use_literal_plus = not args.no_literal_plus

    logger.info(f"Target IMAP server: {host}:{port} | Accounts configured: {len(accounts)}")
    for acc in accounts:
        logger.info(f"  -> Mailbox #{acc.index}: {acc.email}")

    results = {}

    if args.ab_test and len(accounts) >= 2:
        stats_single = await run_phase(
            "PHASE-A (Single Mailbox Baseline)",
            accounts[:1],
            host,
            port,
            duration_secs,
            args.batch_kb,
            use_literal_plus,
        )
        await asyncio.sleep(3.0)
        stats_multi = await run_phase(
            f"PHASE-B (Active-Active Striping N={len(accounts)})",
            accounts,
            host,
            port,
            duration_secs,
            args.batch_kb,
            use_literal_plus,
        )
        print_ab_comparison(stats_single, stats_multi)
        results = {
            "single_mailbox": stats_single.to_summary_dict(),
            "multi_mailbox": stats_multi.to_summary_dict(),
        }
    else:
        stats_run = await run_phase(
            f"Active-Active Multi-Mailbox (N={len(accounts)})",
            accounts,
            host,
            port,
            duration_secs,
            args.batch_kb,
            use_literal_plus,
        )
        results = stats_run.to_summary_dict()

    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"Detailed JSON metrics saved to {STATS_FILE}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
