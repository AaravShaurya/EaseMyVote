# test_vote_tally.py

from main import recalculate_vote_tally
from database import SessionLocal

db = SessionLocal()
recalculate_vote_tally(db)
db.close()
