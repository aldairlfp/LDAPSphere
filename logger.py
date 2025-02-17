import logging
import os

from middleware.utils import get_local_address

base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, f"logs.log")

# # Ensure the log directory exists
# if not os.path.exists(base_dir):
#     os.makedirs(base_dir)

# Configure logging
logging.basicConfig(
    filename=log_dir,  # Log file
    filemode="a",  # Append logs instead of overwriting
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,  # Log only INFO level and above
)

# Create a logger instance
logger = logging.getLogger(__name__)
