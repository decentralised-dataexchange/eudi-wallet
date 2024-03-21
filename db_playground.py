import asyncio
import logging

from eudi_wallet.ebsi.entry_points.server.start import AppLogger, DBSetup
from eudi_wallet.ebsi.repositories.data_agreement import (
    SqlAlchemyDataAgreementRepository,
)


async def main():
    database_user = "eudiwallet"
    database_password = "secret"
    database_host = "localhost"
    database_port = 5432
    database_db = "eudiwalletdb"

    database_url = f"postgresql+psycopg2://{database_user}:{database_password}@{database_host}:{database_port}/{database_db}"
    db_session = DBSetup(database_url).setup_db()
    logger = AppLogger(__name__, level=logging.DEBUG).logger
    data_agreement_repository = SqlAlchemyDataAgreementRepository(
        session=db_session, logger=logger
    )
    with data_agreement_repository as repo:
        data_agreements = repo.get_all()
        data_agreements_json = [data_agreement.to_dict() for data_agreement in data_agreements]
        print("debug")
        print(data_agreements_json)


asyncio.run(main())
