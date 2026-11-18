from webscanpro.modules.base import BaseSecurityModule, FindingData
from webscanpro.modules.headers_cookies import HeadersCookiesModule
from webscanpro.modules.sqli import SQLInjectionModule
from webscanpro.modules.xss import XSSModule
from webscanpro.modules.auth_session import AuthSessionModule
from webscanpro.modules.access_control import AccessControlModule

MODULE_REGISTRY = {
    "headers": HeadersCookiesModule,
    "sqli": SQLInjectionModule,
    "xss": XSSModule,
    "auth": AuthSessionModule,
    "idor": AccessControlModule,
}

def get_module(module_name: str, session=None, logger=None):
    cls = MODULE_REGISTRY.get(module_name.lower())
    if cls:
        return cls(session=session, logger=logger)
    return None

__all__ = [
    "BaseSecurityModule",
    "FindingData",
    "HeadersCookiesModule",
    "SQLInjectionModule",
    "XSSModule",
    "AuthSessionModule",
    "AccessControlModule",
    "MODULE_REGISTRY",
    "get_module",
]
