import sys
import asyncio

# On Windows in sandboxed environment, SelectorEventLoop avoids Proactor loopback socketpair deadlocks
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass
