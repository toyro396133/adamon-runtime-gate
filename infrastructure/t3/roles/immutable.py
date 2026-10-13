"""Owned immutable snapshots of privileged configuration, never caller aliases."""
from collections.abc import Mapping
from types import MappingProxyType

def freeze(value):
    if isinstance(value,Mapping):return MappingProxyType({key:freeze(item) for key,item in value.items()})
    if isinstance(value,(tuple,list)):return tuple(freeze(item) for item in value)
    if isinstance(value,(set,frozenset)):return frozenset(freeze(item) for item in value)
    if isinstance(value,bytearray):return bytes(value)
    return value
