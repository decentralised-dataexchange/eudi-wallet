from enum import Enum


class OrganisationRoles(Enum):
    Issuer = "Issuer"
    TrustedIssuer = "TI"
    TrustedAccreditationOrganisation = "TAO"
    RootTrustedAccreditationOrganisation = "RootTAO"


class DataAgreementExchangeModes(Enum):
    DataSource = "data-source"
    DataUsingService = "data-using-service"
