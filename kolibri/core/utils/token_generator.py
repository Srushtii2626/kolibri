import time

from django.conf import settings
from django.utils.crypto import constant_time_compare
from django.utils.crypto import salted_hmac
from django.utils.http import base36_to_int
from django.utils.http import int_to_base36

TOKEN_EXPIRE_LIMIT = 900  # 15 minutes

# Kept the same as django.contrib.auth.tokens.PasswordResetTokenGenerator's
# defaults so that tokens issued before this class stopped subclassing it
# remain valid.
KEY_SALT = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
ALGORITHM = "sha256"


class TokenGenerator:
    """
    Generates and checks tokens for a user id that:
      - expire the token after some seconds, instead of one day
    """

    def make_token(self, user_id):
        """
        Returns a token that can be used for TOKEN_EXPIRE_LIMIT seconds
        """
        return self._make_token_with_timestamp(user_id, int(time.time()))

    def check_token(self, user_id, token):
        """
        Check that a token is valid within the expiration time window.
        """
        if not (user_id and token):
            return False
        # Parse the token
        try:
            ts_b36, _hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(
            self._make_token_with_timestamp(user_id, ts), token
        ):
            return False

        # Check the timestamp is within limit
        return time.time() - ts <= TOKEN_EXPIRE_LIMIT

    def _make_token_with_timestamp(self, user_id, timestamp):
        """
        Only the user id and the timestamp are hashed, to allow us to check
        the token before we have imported the remote user.
        """
        hash_string = salted_hmac(
            KEY_SALT,
            f"{user_id}{timestamp}",
            secret=settings.SECRET_KEY,
            algorithm=ALGORITHM,
        ).hexdigest()[::2]  # Limit to shorten the token
        return f"{int_to_base36(timestamp)}-{hash_string}"
