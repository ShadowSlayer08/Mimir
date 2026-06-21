"""pytest bootstrap — put the repo root on sys.path so tests can import the
engine modules (nmap_analyzer, modules, attack_path_engine, assess), which use
repo-root-level imports among themselves."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
