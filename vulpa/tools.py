"""
tools.py

Some handy functions that do stuff during the parsing/rendering process
"""

import os


def _flush_refs_for_remediation(ref: dict):
    new = dict(ref)
    if new.get('FSTEC'):
        del new['FSTEC']
    return new

def _check_reports_dir(dirname: str):
    if not os.path.exists(dirname):
        os.mkdir(dirname)