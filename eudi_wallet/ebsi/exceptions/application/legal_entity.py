class StatusListNotFoundError(Exception):
    pass


class CreateCredentialOfferError(Exception):
    pass


class ValidateDataAttributeValuesAgainstDataAttributesError(Exception):
    pass


class UpdateCredentialOfferError(Exception):
    pass


class InvalidStateInIDTokenResponseError(Exception):
    pass


class InvalidAuthorisationCodeError(Exception):
    pass


class InvalidPreAuthorisedCodeError(Exception):
    pass


class InvalidUserPinError(Exception):
    pass


class InvalidClientError(Exception):
    pass


class InvalidCodeVerifierError(Exception):
    pass


class CreateAccessTokenError(Exception):
    pass


class CredentialOfferNotFoundError(Exception):
    pass


class CredentialOfferIsPreAuthorizedError(Exception):
    pass


class UserPinRequiredError(Exception):
    pass


class ClientIdRequiredError(Exception):
    pass
