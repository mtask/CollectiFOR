from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_engine = None
_Session = None

def init_db(db_file: str):
    """Initialize engine and session factory"""
    global _engine, _Session
    _engine = create_engine(f"sqlite:///{db_file}", future=True)
    _Session = sessionmaker(bind=_engine)

def get_session():
    """Return a new SQLAlchemy session"""
    if _Session is None:
        raise RuntimeError("Database not initialized. Call init_db(db_file) first.")
    return _Session()
