#!/usr/bin/env python3
"""
IMAP Full Duplex High-Throughput Soak Test for ANet ASTP-over-IMAPS:993
======================================================================
Универсальный парсер:
  - Прямое бинарное извлечение Base64 тела после заголовков (\\r\\n\\r\\n);
  - Корректный разбор UID из ответа Mail.ru (UID до или ПОСЛЕ {len});
  - Читает литерал побайтово readexactly(len);
  - Включает скользящее окно Backpressure (max 20 in-flight).
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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

LOG_FILE = "imap_soak_speed.log"
STATS_FILE = "imap_soak_stats.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8"),
    ],
)
logger = logging.getLogger("IMAP-SPEED")


@dataclass
class SoakStats:
    start_time: float = field(default_factory=time.time)
    duration_secs: float = 300.0

    cli_tx_batches: int = 0
    cli_tx_bytes: int = 0
    srv_tx_batches: int = 0
    srv_tx_bytes: int = 0

    cli_rx_batches: int = 0
    cli_rx_bytes: int = 0
    srv_rx_batches: int = 0
    srv_rx_bytes: int = 0

    rtt_samples: List[float] = field(default_factory=list)
    append_latency_samples: List[float] = field(default_factory=list)
    fetch_latency_samples: List[float] = field(default_factory=list)

    blind_window_hits: int = 0
    uid_fetch_duplicate_hits: int = 0
    reconnect_events: int = 0
    throttled_events: int = 0
    overquota_events: int = 0
    errors: List[str] = field(default_factory=list)

    def print_summary(self):
        elapsed = max(0.1, time.time() - self.start_time)
        rtt_sorted = sorted(self.rtt_samples)
        rtt_p50 = rtt_sorted[len(rtt_sorted) // 2] if rtt_sorted else 0.0
        rtt_p95 = rtt_sorted[int(len(rtt_sorted) * 0.95)] if rtt_sorted else 0.0

        app_sorted = sorted(self.append_latency_samples)
        app_p50 = app_sorted[len(app_sorted) // 2] if app_sorted else 0.0

        fet_sorted = sorted(self.fetch_latency_samples)
        fet_p50 = fet_sorted[len(fet_sorted) // 2] if fet_sorted else 0.0

        cli_tx_mib = self.cli_tx_bytes / (1024 * 1024)
        cli_rx_mib = self.cli_rx_bytes / (1024 * 1024)
        uplink_mbps = (self.cli_tx_bytes * 8) / (elapsed * 1_000_000)
        downlink_mbps = (self.cli_rx_bytes * 8) / (elapsed * 1_000_000)

        summary = f"""
========================================================================
       ИТОГОВЫЙ ОТЧЕТ ВЫСОКОСКОРОСТНОГО ТЕСТИРОВАНИЯ IMAP
========================================================================
Время тестирования:            {elapsed:.1f} сек ({elapsed / 60.0:.2f} мин)
Отправлено клиентом (Uplink):  {self.cli_tx_batches} батчей ({cli_tx_mib:.2f} МиБ | {uplink_mbps:.3f} Mbps)
Принято сервером (Uplink):     {self.srv_rx_batches} батчей ({self.srv_rx_bytes / (1024*1024):.2f} МиБ)
Отправлено сервером (Downlink):{self.srv_tx_batches} батчей ({self.srv_tx_bytes / (1024*1024):.2f} МиБ)
Принято клиентом (Downlink):   {self.cli_rx_batches} батчей ({cli_rx_mib:.2f} МиБ | {downlink_mbps:.3f} Mbps)
Потери пакетов:                {max(0, self.cli_tx_batches - self.srv_rx_batches)} Uplink, {max(0, self.srv_tx_batches - self.cli_rx_batches)} Downlink

МЕДИАННЫЕ ЗАДЕРЖКИ (Data Plane):
- End-to-End RTT (Client -> Server -> Client):  p50={rtt_p50:.1f} мс | p95={rtt_p95:.1f} мс (всего замеров: {len(self.rtt_samples)})
- Задержка команды APPEND (Mail.ru):            p50={app_p50:.1f} мс
- Задержка команды UID FETCH (Mail.ru):         p50={fet_p50:.1f} мс

АНАЛИЗ КРИТИЧЕСКИХ МЕСТ ПРОТОКОЛА:
- Попаданий в «Слепое окно» (* EXISTS вне IDLE):{self.blind_window_hits}
- Аномалий UID FETCH <last+1>:* (дубликаты):     {self.uid_fetch_duplicate_hits}
- Превышений рейт-лимита (NO [THROTTLED]):      {self.throttled_events}
- Превышений квоты ящика (NO [OVERQUOTA]):      {self.overquota_events}
- Переподключений сокетов:                      {self.reconnect_events}
- Ошибок парсинга:                              {len(self.errors)}
========================================================================
"""
        logger.info(summary)
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "elapsed_secs": elapsed,
                    "cli_tx_batches": self.cli_tx_batches,
                    "cli_tx_bytes": self.cli_tx_bytes,
                    "cli_tx_mbps": uplink_mbps,
                    "cli_rx_batches": self.cli_rx_batches,
                    "cli_rx_bytes": self.cli_rx_bytes,
                    "cli_rx_mbps": downlink_mbps,
                    "rtt_p50_ms": rtt_p50,
                    "rtt_p95_ms": rtt_p95,
                    "rtt_samples_count": len(self.rtt_samples),
                    "append_p50_ms": app_p50,
                    "fetch_p50_ms": fet_p50,
                    "blind_window_hits": self.blind_window_hits,
                    "uid_duplicate_hits": self.uid_fetch_duplicate_hits,
                    "throttled_events": self.throttled_events,
                    "overquota_events": self.overquota_events,
                    "reconnect_events": self.reconnect_events,
                    "errors_sample": self.errors[:10],
                },
                f,
                indent=2,
            )


class RobustImapClient:
    def __init__(self, host: str, port: int, email_addr: str, password: str, label: str, stats: SoakStats):
        self.host = host
        self.port = port
        self.email_addr = email_addr
        self.password = password
        self.label = label
        self.stats = stats

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.tag_counter = 0
        self.pending_exists = False
        self.in_idle = False
        self.idle_tag = ""
        self.logger = logging.getLogger(f"IMAP:{label}")

    def next_tag(self) -> str:
        self.tag_counter += 1
        return f"A{self.tag_counter:04d}"

    async def connect(self):
        ssl_ctx = ssl.create_default_context()
        self.logger.info(f"Connecting to {self.host}:{self.port} (TLS)...")
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=ssl_ctx
        )
        banner = await self.readline()
        self.logger.debug(f"Banner: {banner.strip()}")

        tag = self.next_tag()
        await self.send_line(f'{tag} LOGIN "{self.email_addr}" "{self.password}"')
        resp = await self.read_until_tagged(tag)
        if not resp[-1].startswith(f"{tag} OK"):
            raise RuntimeError(f"Login failed: {resp[-1]}")
        self.logger.info(f"Logged in successfully as {self.email_addr}")

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
                self.stats.blind_window_hits += 1
            self.pending_exists = True

        return line

    async def read_until_tagged(self, tag: str, timeout_sec: float = 15.0) -> List[str]:
        lines = []
        start = time.time()
        while True:
            if time.time() - start > timeout_sec:
                raise asyncio.TimeoutError(f"Timeout waiting for tagged response {tag}")
            line = await self.readline()
            lines.append(line)
            if line.startswith(f"{tag} OK") or line.startswith(f"{tag} NO") or line.startswith(f"{tag} BAD"):
                break
        return lines

    async def select(self, folder: str):
        tag = self.next_tag()
        await self.send_line(f'{tag} SELECT "{folder}"')
        resp = await self.read_until_tagged(tag)
        if not resp[-1].startswith(f"{tag} OK"):
            raise RuntimeError(f"SELECT {folder} failed: {resp[-1]}")
        self.logger.info(f'Selected folder "{folder}"')

    async def append_message(self, folder: str, subject: str, payload_bytes: bytes) -> float:
        t0 = time.time()
        b64_content = base64.b64encode(payload_bytes).decode("ascii")
        b64_chunked = "\r\n".join(b64_content[i:i+76] for i in range(0, len(b64_content), 76))

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
        await self.send_line(f'{tag} APPEND "{folder}" (\\Seen \\Draft) {{{len(msg_raw)}}}')

        while True:
            line = await self.readline()
            if line.startswith("+"):
                break
            if line.startswith(f"{tag} NO") or line.startswith(f"{tag} BAD"):
                if "THROTTLED" in line:
                    self.stats.throttled_events += 1
                if "OVERQUOTA" in line:
                    self.stats.overquota_events += 1
                raise RuntimeError(f"APPEND step 1 rejected: {line.strip()}")

        self.writer.write(msg_raw + b"\r\n")
        await self.writer.drain()

        resp = await self.read_until_tagged(tag)
        t_append = (time.time() - t0) * 1000.0
        self.stats.append_latency_samples.append(t_append)

        if not resp[-1].startswith(f"{tag} OK"):
            if "THROTTLED" in resp[-1]:
                self.stats.throttled_events += 1
            if "OVERQUOTA" in resp[-1]:
                self.stats.overquota_events += 1
            raise RuntimeError(f"APPEND step 2 failed: {resp[-1]}")

        return t_append

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
                raise RuntimeError(f"IDLE rejected: {line}")

    async def exit_idle(self):
        if not self.in_idle:
            return
        await self.send_line("DONE")
        self.in_idle = False
        try:
            await self.read_until_tagged(self.idle_tag, timeout_sec=5.0)
        except asyncio.TimeoutError:
            self.logger.warning("Timeout waiting for IDLE tagged response after DONE")

    async def fetch_messages_robust(self, last_uid: int) -> Tuple[List[Tuple[int, str, bytes]], int, float]:
        """
        Универсальный и надёжный парсер:
        1. Отправляет UID FETCH <start>:* (UID BODY.PEEK[])
        2. Считывает ровно msg_len байт через readexactly
        3. Находит Subject в заголовках и декодирует чистый Base64 после \\r\\n\\r\\n напрямую!
        """
        t0 = time.time()
        tag = self.next_tag()
        start_uid = last_uid + 1
        await self.send_line(f"{tag} UID FETCH {start_uid}:* (UID BODY.PEEK[])")

        messages = []
        new_max_uid = last_uid

        while True:
            line = await self.readline()
            if line.startswith(f"{tag} OK") or line.startswith(f"{tag} NO") or line.startswith(f"{tag} BAD"):
                break

            lit_m = re.search(r"\{(\d+)\}", line)
            if not lit_m:
                continue

            msg_len = int(lit_m.group(1))

            # 1. Читаем ровно msg_len байт письма
            msg_bytes = await self.reader.readexactly(msg_len)

            # 2. Дочитываем хвост текущей строки FETCH (там закрывающая скобка и UID!)
            rest_line = await self.readline()

            # 3. Ищем UID в заголовке или в хвосте строки
            full_meta = line + " " + rest_line
            uid_m = re.search(r"UID\s+(\d+)", full_meta, re.IGNORECASE)
            if not uid_m:
                continue

            uid = int(uid_m.group(1))
            if uid <= last_uid:
                self.stats.uid_fetch_duplicate_hits += 1
                continue

            new_max_uid = max(new_max_uid, uid)

            # 4. Прямой разбор RFC 822 без капризных библиотек:
            # Ищем границу заголовков и тела (\r\n\r\n или \n\n)
            try:
                split_idx = msg_bytes.find(b"\r\n\r\n")
                if split_idx != -1:
                    hdr_raw = msg_bytes[:split_idx].decode("latin1", errors="replace")
                    body_raw = msg_bytes[split_idx+4:]
                else:
                    split_idx = msg_bytes.find(b"\n\n")
                    hdr_raw = msg_bytes[:split_idx].decode("latin1", errors="replace")
                    body_raw = msg_bytes[split_idx+2:]

                # Извлекаем Subject
                subject = ""
                for h in hdr_raw.splitlines():
                    if h.lower().startswith("subject:"):
                        subject = h.split(":", 1)[1].strip()
                        break

                # Чистим тело от пробелов и переводов строк
                clean_b64 = body_raw.replace(b"\r", b"").replace(b"\n", b"").strip()
                payload = base64.b64decode(clean_b64)
                messages.append((uid, subject, payload))

            except Exception as e:
                self.stats.errors.append(f"UID {uid}: {e}")
                self.logger.error(f"Failed to extract payload UID {uid}: {e}")

        t_fetch = (time.time() - t0) * 1000.0
        self.stats.fetch_latency_samples.append(t_fetch)
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

    async def close(self):
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass


async def run_server_worker(
    email_addr: str,
    srv_pass: str,
    host: str,
    port: int,
    stats: SoakStats,
    stop_event: asyncio.Event,
):
    logger.info("[SRV] Starting Server Workers (Reader & Writer)...")
    srv_reader = RobustImapClient(host, port, email_addr, srv_pass, "SRV_READER", stats)
    srv_writer = RobustImapClient(host, port, email_addr, srv_pass, "SRV_WRITER", stats)

    await srv_reader.connect()
    await srv_reader.select("Drafts")

    await srv_writer.connect()
    await srv_writer.select("Drafts")

    last_seen_uid = 0
    cleanup_queue: List[int] = []
    echo_queue: asyncio.Queue = asyncio.Queue()

    async def srv_writer_loop():
        while not stop_event.is_set():
            try:
                if cleanup_queue:
                    to_clean = cleanup_queue[:]
                    cleanup_queue.clear()
                    await srv_writer.expunge_uids(to_clean)

                try:
                    target_id, payload = await asyncio.wait_for(echo_queue.get(), timeout=0.05)
                    subj = f"[ID: {target_id}]"
                    await srv_writer.append_message("Notes", subj, payload)
                    stats.srv_tx_batches += 1
                    stats.srv_tx_bytes += len(payload)
                except asyncio.TimeoutError:
                    pass

            except Exception as e:
                logger.error(f"[SRV_WRITER] Error: {e}")
                stats.errors.append(f"SRV_WRITER: {e}")
                await asyncio.sleep(0.5)

    writer_task = asyncio.create_task(srv_writer_loop())

    try:
        while not stop_event.is_set():
            if not srv_reader.pending_exists:
                await srv_reader.enter_idle()
                t_idle_start = time.time()
                while not srv_reader.pending_exists and not stop_event.is_set():
                    if time.time() - t_idle_start > 30.0:
                        break
                    await asyncio.sleep(0.005)
                await srv_reader.exit_idle()

            srv_reader.pending_exists = False

            msgs, new_max, _ = await srv_reader.fetch_messages_robust(last_seen_uid)
            last_seen_uid = new_max

            for uid, subject, payload in msgs:
                cleanup_queue.append(uid)
                stats.srv_rx_batches += 1
                stats.srv_rx_bytes += len(payload)

                id_match = re.search(r"\[ID:\s*([^\]]+)\]", subject)
                if id_match:
                    cli_target = id_match.group(1).split(":")[-1]
                    await echo_queue.put((cli_target, payload))

    finally:
        writer_task.cancel()
        await srv_reader.close()
        await srv_writer.close()


async def run_client_worker(
    email_addr: str,
    cli_pass: str,
    host: str,
    port: int,
    stats: SoakStats,
    stop_event: asyncio.Event,
    session_id: str,
    batch_kb: int,
):
    logger.info(f"[CLI] Starting Client Workers (Batch Size: {batch_kb} KB)...")
    cli_reader = RobustImapClient(host, port, email_addr, cli_pass, "CLI_READER", stats)
    cli_writer = RobustImapClient(host, port, email_addr, cli_pass, "CLI_WRITER", stats)

    await cli_reader.connect()
    await cli_reader.select("Notes")

    await cli_writer.connect()
    await cli_writer.select("Notes")

    last_seen_uid = 0
    cleanup_queue: List[int] = []
    sent_timestamps: Dict[int, float] = {}
    seq_counter = 0

    payload_padding = b"X" * max(64, batch_kb * 1024 - 64)

    async def cli_sender_loop():
        nonlocal seq_counter
        while not stop_event.is_set():
            try:
                unacked = len(sent_timestamps)
                if unacked > 15:
                    await asyncio.sleep(0.05)
                    continue

                seq_counter += 1
                now = time.time()
                header = seq_counter.to_bytes(8, "big") + int(now * 1_000_000).to_bytes(8, "big")
                payload = header + payload_padding
                sent_timestamps[seq_counter] = now

                subj = f"ANet-Data [ID: srv01:{session_id}]"
                await cli_writer.append_message("Drafts", subj, payload)
                stats.cli_tx_batches += 1
                stats.cli_tx_bytes += len(payload)

                if cleanup_queue:
                    to_clean = cleanup_queue[:]
                    cleanup_queue.clear()
                    await cli_writer.expunge_uids(to_clean)

                await asyncio.sleep(0.01)

            except Exception as e:
                logger.error(f"[CLI_WRITER] Error: {e}")
                stats.errors.append(f"CLI_WRITER: {e}")
                await asyncio.sleep(0.5)

    sender_task = asyncio.create_task(cli_sender_loop())

    try:
        while not stop_event.is_set():
            if not cli_reader.pending_exists:
                await cli_reader.enter_idle()
                t_idle_start = time.time()
                while not cli_reader.pending_exists and not stop_event.is_set():
                    if time.time() - t_idle_start > 30.0:
                        break
                    await asyncio.sleep(0.005)
                await cli_reader.exit_idle()

            cli_reader.pending_exists = False

            msgs, new_max, _ = await cli_reader.fetch_messages_robust(last_seen_uid)
            last_seen_uid = new_max

            for uid, subject, payload in msgs:
                cleanup_queue.append(uid)
                stats.cli_rx_batches += 1
                stats.cli_rx_bytes += len(payload)

                if len(payload) >= 16:
                    seq = int.from_bytes(payload[0:8], "big")
                    if seq in sent_timestamps:
                        rtt = (time.time() - sent_timestamps.pop(seq)) * 1000.0
                        stats.rtt_samples.append(rtt)
                        if stats.cli_rx_batches % 10 == 0:
                            elapsed = max(0.1, time.time() - stats.start_time)
                            cur_mbps = (stats.cli_rx_bytes * 8) / (elapsed * 1_000_000)
                            logger.info(
                                f"[ECHO #{seq}] RTT: {rtt:.1f} ms | "
                                f"Total RX: {stats.cli_rx_bytes / (1024*1024):.2f} MiB ({cur_mbps:.2f} Mbps) | "
                                f"InFlight: {len(sent_timestamps)}"
                            )

    finally:
        sender_task.cancel()
        await cli_reader.close()
        await cli_writer.close()


async def main():
    parser = argparse.ArgumentParser(description="ANet IMAP High-Throughput Soak Test")
    parser.add_argument("--email", default=os.getenv("ANET_IMAP_EMAIL"), required=not os.getenv("ANET_IMAP_EMAIL"), help="Email address")
    parser.add_argument("--cli-pass", default=os.getenv("ANET_IMAP_CLI_PASS"), required=not os.getenv("ANET_IMAP_CLI_PASS"), help="App password for Client")
    parser.add_argument("--srv-pass", default=os.getenv("ANET_IMAP_SRV_PASS"), required=not os.getenv("ANET_IMAP_SRV_PASS"), help="App password for Server")
    parser.add_argument("--host", default="imap.mail.ru", help="IMAP server host (default: imap.mail.ru)")
    parser.add_argument("--port", type=int, default=993, help="IMAP port (default: 993)")
    parser.add_argument("--duration-mins", type=int, default=5, help="Test duration in minutes (default: 5)")
    parser.add_argument("--batch-kb", type=int, default=32, help="Payload batch size in KB (default: 32)")
    args = parser.parse_args()

    stats = SoakStats(duration_secs=args.duration_mins * 60.0)
    stop_event = asyncio.Event()
    session_id = f"spd_{int(time.time()):x}"

    logger.info(f"Starting High-Throughput Soak Test on {args.host}:{args.port}")
    logger.info(f"Account: {args.email} | Duration: {args.duration_mins} min | Batch Size: {args.batch_kb} KB")

    server_coro = run_server_worker(
        args.email, args.srv_pass, args.host, args.port, stats, stop_event
    )
    client_coro = run_client_worker(
        args.email, args.cli_pass, args.host, args.port, stats, stop_event, session_id, args.batch_kb
    )

    async def progress_reporter():
        while not stop_event.is_set():
            await asyncio.sleep(30.0)
            elapsed = max(0.1, time.time() - stats.start_time)
            tx_mbps = (stats.cli_tx_bytes * 8) / (elapsed * 1_000_000)
            rx_mbps = (stats.cli_rx_bytes * 8) / (elapsed * 1_000_000)
            logger.info(
                f"[SPEED] {elapsed/60.0:.1f}/{args.duration_mins} min | "
                f"TX: {stats.cli_tx_bytes/(1024*1024):.1f} MiB ({tx_mbps:.2f} Mbps) | "
                f"RX: {stats.cli_rx_bytes/(1024*1024):.1f} MiB ({rx_mbps:.2f} Mbps) | "
                f"BlindWindow: {stats.blind_window_hits}"
            )

    reporter_task = asyncio.create_task(progress_reporter())

    try:
        await asyncio.wait(
            [
                asyncio.create_task(server_coro),
                asyncio.create_task(client_coro),
                asyncio.create_task(asyncio.sleep(stats.duration_secs)),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
    except KeyboardInterrupt:
        logger.warning("Interrupted by user. Shutting down gracefully...")
    finally:
        stop_event.set()
        reporter_task.cancel()
        await asyncio.sleep(1.0)
        stats.print_summary()


if __name__ == "__main__":
    asyncio.run(main())
