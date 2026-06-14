import logging
import os
from datetime import datetime

def setup_logger(workspace_dir="workspace"):
    os.makedirs(workspace_dir, exist_ok=True)
    log_file = os.path.join(workspace_dir, f"utsu_execution_{datetime.now().strftime('%Y%m%d')}.log")

    # Create a custom logger
    logger = logging.getLogger("UTSU")
    logger.setLevel(logging.DEBUG)

    # Avoid adding multiple handlers if logger is already initialized
    if not logger.handlers:
        # File Handler (Detailed, catches everything including traces)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s')
        file_handler.setFormatter(file_format)

        # Console Handler (Clean, user-facing)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('[%(levelname)s] %(message)s')
        console_handler.setFormatter(console_format)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

log = setup_logger()