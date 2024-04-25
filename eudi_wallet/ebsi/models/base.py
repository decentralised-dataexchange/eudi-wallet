from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


def import_models():
    from eudi_wallet.ebsi.models.credential_offer import (  # noqa: F401
        CredentialOfferModel,
    )
    from eudi_wallet.ebsi.models.credential_revocation_status_list import (  # noqa: F401
        CredentialRevocationStatusListModel,
    )
    from eudi_wallet.ebsi.models.data_agreement import DataAgreementModel  # noqa: F401
    from eudi_wallet.ebsi.models.organisation import OrganisationModel  # noqa: F401
    from eudi_wallet.ebsi.models.v2.data_agreement import (
        V2DataAgreementModel,
    )  # noqa: F401
    from eudi_wallet.ebsi.models.v2.issue_credential_record import (
        IssueCredentialRecordModel,
    )  # noqa: F401
