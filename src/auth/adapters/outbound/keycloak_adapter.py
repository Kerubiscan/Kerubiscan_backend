from typing import Optional, Dict, Any
from keycloak import KeycloakOpenID
from src.core.config import settings
from src.auth.ports.outbound.token_decoder import TokenDecoderPort

keycloak_openid = KeycloakOpenID(
    server_url=settings.KEYCLOAK_SERVER_URL,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    realm_name=settings.KEYCLOAK_REALM_NAME,
    client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
    verify=True
)

class KeycloakAdapter(TokenDecoderPort):
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            # We fetch public keys dynamically or use python-keycloak's decode_token
            # python-keycloak supports decoding the token using the realm's public key
            decoded = keycloak_openid.decode_token(token)
            return decoded
        except Exception as e:
            import logging
            logging.error(f"Failed to decode token: {e}")
            return None
