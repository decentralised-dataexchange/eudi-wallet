from enum import Enum


class LegalEntityRoles(Enum):
    TrustedIssuer = "TI"
    TrustedAccreditationOrganisation = "TAO"
    RootTrustedAccreditationOrganisation = "RootTAO"
