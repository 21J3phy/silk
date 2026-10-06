from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    client_id: str


class MailboxError(Exception):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)
