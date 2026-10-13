import os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault("SECRET_KEY", "test-secret-test-secret-test-secret-1234")
