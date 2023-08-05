from enum import Enum


class EventTypes(Enum):
    OnboardTrustedIssuer = "OnboardTrustedIssuer"
    OnboardTrustedAccreditationOrganisation = "OnboardTrustedAccreditationOrganisation"
    OnboardRootTrustedAccreditationOrganisation = "OnboardRootTrustedAccreditationOrganisation"
