import asyncio
import html
import threading
import uuid
from typing import Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Message, Update
from telegram.ext import Application, CallbackQueryHandler, ContextTypes


class TelegramGate:
    """
    Sends an inline-keyboard alert to Telegram and blocks the calling thread
    until the user taps a button or the timeout expires (auto-deny).
    """

    def __init__(self, bot_token: str, chat_id: str, timeout_seconds: int = 30):
        self.chat_id = chat_id
        self.timeout_seconds = timeout_seconds
        self._pending: dict[str, dict] = {}  # op_id -> {event, result, msg_id}
        self._app: Optional[Application] = None
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()

        t = threading.Thread(target=self._run_loop, args=(bot_token,), daemon=True)
        t.start()

        if not self._ready.wait(timeout=20):
            raise RuntimeError("Telegram bot failed to connect within 20s")
        print("[TelegramGate] Connected — @jackdiskguard_bot")

    # ------------------------------------------------------------------ #
    #  Internal async loop                                                 #
    # ------------------------------------------------------------------ #

    def _run_loop(self, bot_token: str):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start(bot_token))

    async def _start(self, bot_token: str):
        self._app = Application.builder().token(bot_token).build()
        self._app.add_handler(CallbackQueryHandler(self._on_button))
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)
        self._ready.set()
        await asyncio.get_event_loop().create_future()

    async def _on_button(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()

        try:
            op_id, decision = query.data.split(":", 1)
        except ValueError:
            return

        slot = self._pending.get(op_id)
        if slot and not slot["event"].is_set():
            slot["result"] = decision
            slot["event"].set()

        labels = {
            "allow_once":   "✅ Allowed once",
            "allow_always": "🔒 Always allowed",
            "allow_dir":    "📁 Directory allowed",
            "deny":         "❌ Denied",
        }
        await query.edit_message_text(
            query.message.text + f"\n\n→ <b>{labels.get(decision, decision)}</b>",
            parse_mode="HTML",
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def ask(self, op: dict, timeout_override: Optional[int] = None) -> str:
        """
        Block until the user responds or timeout expires (auto-deny).
        Returns: allow_once | allow_always | allow_dir | deny
        timeout_override: if set, overrides the instance-level timeout for this call.
        """
        op_id = uuid.uuid4().hex[:8]
        event = threading.Event()
        self._pending[op_id] = {"event": event, "result": "deny", "msg_id": None}

        send_future = asyncio.run_coroutine_threadsafe(
            self._send(op, op_id), self._loop
        )
        msg: Message = send_future.result(timeout=10)
        self._pending[op_id]["msg_id"] = msg.message_id

        wait_secs = timeout_override if timeout_override is not None else self.timeout_seconds
        timed_out = not event.wait(timeout=wait_secs)
        slot = self._pending.pop(op_id, {})

        if timed_out:
            asyncio.run_coroutine_threadsafe(
                self._mark_timeout(slot.get("msg_id"), op),
                self._loop,
            )
            return "deny"

        return slot.get("result", "deny")

    def notify(self, text: str):
        """Fire-and-forget alert (no buttons)."""
        asyncio.run_coroutine_threadsafe(
            self._app.bot.send_message(
                chat_id=self.chat_id, text=text, parse_mode="HTML"
            ),
            self._loop,
        )

    # ------------------------------------------------------------------ #
    #  Internals                                                           #
    # ------------------------------------------------------------------ #

    async def _send(self, op: dict, op_id: str) -> Message:
        # Allow callers to provide a custom button layout via op["buttons"]:
        # [[("callback_key", "Button Label"), ...], ...]  (list of rows)
        custom = op.get("buttons")
        if custom:
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton(label, callback_data=f"{op_id}:{key}")
                 for key, label in row]
                for row in custom
            ])
        else:
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("✅ Allow Once",
                                         callback_data=f"{op_id}:allow_once"),
                    InlineKeyboardButton("🔒 Always Allow",
                                         callback_data=f"{op_id}:allow_always"),
                ],
                [
                    InlineKeyboardButton("📁 Allow Dir",
                                         callback_data=f"{op_id}:allow_dir"),
                    InlineKeyboardButton("❌ Deny",
                                         callback_data=f"{op_id}:deny"),
                ],
            ])
        return await self._app.bot.send_message(
            chat_id=self.chat_id,
            text=self._format(op),
            reply_markup=keyboard,
            parse_mode="HTML",
        )

    async def _mark_timeout(self, msg_id: Optional[int], op: dict):
        if msg_id is None:
            return
        path = (op.get("details", {}).get("Path")
                or op.get("details", {}).get("Count", ""))
        try:
            await self._app.bot.edit_message_text(
                chat_id=self.chat_id,
                message_id=msg_id,
                text=(f"⏱ <b>Auto-denied</b> — no response within "
                      f"{self.timeout_seconds}s\n<code>{path}</code>"),
                parse_mode="HTML",
            )
        except Exception:
            pass

    @staticmethod
    def _format(op: dict) -> str:
        action = op.get("action", "UNKNOWN")
        action_upper = action.upper()

        if action == "email_intercept":
            details = op.get("details", {})
            op_raw  = details.get("Operation", "DELETE")
            msgs    = details.get("Messages",  "?")
            dest    = details.get("Destination", "")
            subject = details.get("Subject",   "")
            from_   = details.get("From",      "")
            to_     = details.get("To",        "")
            date_   = details.get("Date",      "")
            proc    = details.get("Process",   "?")
            pid_s   = details.get("PID",       "?")
            op_label_map = {
                "STORE +FLAGS \\Deleted": "Delete email",
                "EXPUNGE":               "Permanently purge deleted emails",
                "MOVE":                  f"Move to {dest}" if dest else "Move email",
            }
            op_label = op_label_map.get(op_raw, op_raw)
            lines = ["🗑 <b>Email Guardian — DELETE intercepted</b>\n"]
            lines.append(f"<b>Action:</b>   <code>{html.escape(op_label)}</code>  (msg {html.escape(str(msgs))})")
            if subject:
                lines.append(f"<b>Subject:</b>  <code>{html.escape(subject)}</code>")
            if from_:
                lines.append(f"<b>From:</b>     <code>{html.escape(from_)}</code>")
            if to_:
                lines.append(f"<b>To:</b>       <code>{html.escape(to_)}</code>")
            if date_:
                lines.append(f"<b>Date:</b>     <code>{html.escape(date_)}</code>")
            lines.append(f"\n<b>Process:</b>  <code>{html.escape(str(proc))}</code>")
            lines.append(f"<b>PID:</b>      <code>{html.escape(str(pid_s))}</code>")
            lines.append("\n<i>Waiting for your decision...</i>")
            return "\n".join(lines)

        if action == "db_intercept":
            details = op.get("details", {})
            risk    = details.get("Risk", "?")
            label   = details.get("Type", "?")
            sql     = details.get("SQL", "")
            process = details.get("Process", "")
            pid_s   = details.get("PID", "")
            icon    = "🔴" if risk == "high" else "🟡"
            lines   = [f"{icon} <b>DB Guardian — {html.escape(str(label))} intercepted</b>\n"]
            lines.append(f"<b>SQL:</b>\n<code>{html.escape(sql)}</code>\n")
            lines.append(f"<b>Risk:</b>     <code>{html.escape(str(risk))}</code>")
            if process:
                lines.append(f"<b>Process:</b>  <code>{html.escape(str(process))}</code>")
            if pid_s:
                lines.append(f"<b>PID:</b>      <code>{html.escape(str(pid_s))}</code>")
            lines.append("\n<i>Waiting for your decision...</i>")
            return "\n".join(lines)

        icon = {
            "DELETE":      "🗑",
            "OVERWRITE":   "✏️",
            "MOVE":        "📦",
            "BULK_DELETE": "⚠️",
        }.get(action_upper, "⚠️")
        lines = [f"{icon} <b>Disk Guardian — {action_upper} intercepted</b>\n"]
        for k, v in op.get("details", {}).items():
            lines.append(f"<b>{html.escape(str(k))}:</b>  <code>{html.escape(str(v))}</code>")
        if op.get("backup_path"):
            lines.append("\n✓ <i>Backup available — will restore if denied</i>")
        else:
            lines.append("\n⚠️ <i>No backup — cannot restore if denied</i>")
        lines.append("\n<i>Waiting for your decision...</i>")
        return "\n".join(lines)
