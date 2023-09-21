from logging import Logger
from typing import List, Optional

from jsonschema import exceptions, validate

from eudi_wallet.ebsi.exceptions.application.organisation import (
    CreateDataAgreementUsecaseError,
)
from eudi_wallet.ebsi.models.data_agreement import DataAgreementModel
from eudi_wallet.ebsi.repositories.data_agreement import (
    SqlAlchemyDataAgreementRepository,
)
from eudi_wallet.ebsi.utils.jsonschema import meta_schema_draft_7


class CreateDataAgreementUsecase:
    def __init__(
        self,
        dataagreement_repository: SqlAlchemyDataAgreementRepository,
        logger: Logger,
    ) -> None:
        self.dataagreement_repository = dataagreement_repository
        self.logger = logger

    def _convert_sentence_to_pascal_case(self, sentence: str) -> str:
        return "".join(word.strip().capitalize() for word in sentence.split())

    def execute(
        self,
        organisation_id: str,
        name: str,
        data_attributes: dict,
        exchange_mode: str,
        credential_types: Optional[List[str]] = None,
    ) -> DataAgreementModel:
        if not credential_types:
            credential_types = [
                "VerifiableCredential",
                "VerifiableAttestation",
                self._convert_sentence_to_pascal_case(name),
            ]

        try:
            validate(instance=data_attributes, schema=meta_schema_draft_7)
        except exceptions.ValidationError as e:
            raise CreateDataAgreementUsecaseError(e.message)
        with self.dataagreement_repository as repo:
            return repo.create(
                organisation_id=organisation_id,
                name=name,
                data_attributes=data_attributes,
                exchange_mode=exchange_mode,
                credential_types=credential_types,
            )
