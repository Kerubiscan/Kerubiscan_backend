from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class TokenDecoderPort(ABC):
    """
    Port for decoding and verifying authentication tokens.
    """
    
    @abstractmethod
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and verify the provided token.
        
        Args:
            token: The raw JWT or bearer token string.
            
        Returns:
            A dictionary containing the decoded payload if valid, None otherwise.
        """
        pass
