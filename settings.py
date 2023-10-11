from typing import Optional
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_env_file(env_file_path: Optional[str] = ".env") -> None:
    """
    Load variables from the specified environment file into the OS environment.

    Reads each line from the specified environment file and, if it is not a comment or empty,
    adds the variable to the OS environment.

    Parameters:
    - env_file_path (str, optional): The path to the environment file. Defaults to ".env".

    Raises:
    - ValueError: If a line in the env file does not contain the '=' character.
    """
    if os.path.exists(env_file_path):
        with open(env_file_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    os.environ[key] = value


load_env_file()

SERVICE_ACCOUNT_KEY = os.path.join(
    BASE_DIR, os.environ.get("SERVICE_ACCOUNT_KEY").strip()
)
REDIS_HOST = os.environ.get("REDIS_HOST")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6378))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_TLS_CERT_PATH = os.path.join(
    BASE_DIR, os.environ.get("REDIS_TLS_CERT_PATH").strip()
)
BASE_URL = os.environ.get("BASE_URL")
