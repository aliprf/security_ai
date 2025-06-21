import threading
import time

import requests
import uvicorn

from client.client import launch_gradio
from commons.logger import get_logger

logger = get_logger(__name__)


def run_server():
    uvicorn.run("server.server:app", host="127.0.0.1", port=8000, log_level="info")


def wait_for_server(host="127.0.0.1", port=8000, timeout=30):
    url = f"http://{host}:{port}/health"
    start = time.time()
    while time.time() - start < timeout:
        try:
            res = requests.get(url)
            if res.status_code == 200:
                logger.info("FastAPI server is ready.")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    msg = f"FastAPI server not available after {timeout} seconds"
    raise TimeoutError(msg)


def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    wait_for_server()

    client_thread = threading.Thread(target=launch_gradio)
    client_thread.start()
    client_thread.join()


if __name__ == "__main__":
    main()
