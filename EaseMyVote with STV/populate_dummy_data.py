# populate_dummy_data.py

import os
from dotenv import load_dotenv

# Load environment variables before importing database
ENV = os.getenv('ENV', 'production')

if ENV == 'testing':
    load_dotenv('.env.test')
else:
    load_dotenv('.env')

import random
import json
from sqlalchemy.orm import Session
from database import Base, SessionLocal, engine
from models import Voter, Candidate, Vote
from datetime import datetime
import hashlib

# Create database tables
Base.metadata.create_all(bind=engine)

# Create a testing session
db = SessionLocal()

# Create dummy candidates
candidate_names = ['Alice', 'Bob', 'Charlie', 'Diana','Julia']
candidates = []

for name in candidate_names:
    candidate = Candidate(name=name, position='MOCC')
    db.add(candidate)
    candidates.append(candidate)

db.commit()

# Fetch candidate IDs
candidate_ids = [candidate.id for candidate in candidates]

# Create dummy voters and votes
num_dummy_voters = 200  # Adjust as needed

for i in range(num_dummy_voters):
    email = f'dummy_voter_{i}@example.com'
    voter = Voter(
        email=email,
        is_verified=True,
        has_voted=True,
        voted_at=datetime.utcnow()
    )
    db.add(voter)
    db.commit()  # Commit to get voter ID

    # Create a dummy vote
    preferences = random.sample(candidate_ids, k=2)  # Random first and second preferences
    vote_preferences = {
        'first_pref': preferences[0],
        'second_pref': preferences[1]
    }

    # Generate a hashed token for the dummy voter
    voting_token = f'dummy_token_{i}'
    hashed_voter_token = hashlib.sha256(voting_token.encode()).hexdigest()

    vote = Vote(
        encrypted_voter_id=hashed_voter_token,
        preferences=json.dumps(vote_preferences)
    )
    db.add(vote)
    db.commit()

db.close()
