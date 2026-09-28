"""Synthetic customer model and demo data. All records are fictional."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Customer:
    name: str
    email: str
    ic_number: str        # Malaysian NRIC, e.g. 991231-14-5678
    card_number: str      # 16-digit credit/debit card
    account_number: str   # bank account number
    phone: str

    def __repr__(self) -> str:  # noqa: D105 — intentional leak
        return (
            f"Customer(name={self.name!r}, email={self.email!r}, "
            f"ic_number={self.ic_number!r}, card_number={self.card_number!r}, "
            f"account_number={self.account_number!r}, phone={self.phone!r})"
        )


DEMO_CUSTOMERS: list[Customer] = [
    Customer(
        name="Alice Tan",
        email="alice@example.com",
        ic_number="991231-14-5678",
        card_number="4111111111111111",
        account_number="1234567890",
        phone="+60123456789",
    ),
    Customer(
        name="Bob Lim",
        email="bob.lim@mail.com",
        ic_number="870405-10-1234",
        card_number="5500005555555559",
        account_number="9876543210",
        phone="0198765432",
    ),
]
