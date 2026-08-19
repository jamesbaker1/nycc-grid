"""pygrid: node agent, client, and crypto for the new york compute club grid.

jobs and results are libsodium sealed boxes to the recipient key. the coordinator
routes ciphertext only. see docs/THREAT_MODEL.md for what that does and does not buy.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
