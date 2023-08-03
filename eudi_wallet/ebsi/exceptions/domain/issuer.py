class CredentialRequestError(Exception):
    pass


class CredentialDeserializationError(Exception):
    pass


class InvalidIssuerStateTokenError(Exception):
    pass


class ExpiredPreAuthorisedCodeTokenError(Exception):
    pass


class CredentialPendingError(Exception):
    pass


class CredentialRevocationStatusListNotFoundError(Exception):
    pass


class CredentialOfferRevocationError(Exception):
    pass
