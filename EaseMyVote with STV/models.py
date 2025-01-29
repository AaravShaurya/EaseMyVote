# models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from database import Base  # Import Base from database.py

class Voter(Base):
    __tablename__ = 'voters'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    is_verified = Column(Boolean, default=False)
    has_voted = Column(Boolean, default=False)
    encrypted_id = Column(String)
    voted_at = Column(DateTime)  # Field to track when the voter last voted

class Candidate(Base):
    __tablename__ = 'candidates'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    position = Column(String, nullable=False)

    # Relationship to RoundResult
    round_results = relationship("RoundResult", back_populates="candidate")

class Vote(Base):
    __tablename__ = 'votes'
    id = Column(Integer, primary_key=True, index=True)
    encrypted_voter_id = Column(String)
    preferences = Column(String)  # JSON string of preferences

class RoundResult(Base):
    __tablename__ = 'round_results'
    id = Column(Integer, primary_key=True, index=True)
    round_number = Column(Integer, nullable=False)
    candidate_id = Column(Integer, ForeignKey('candidates.id'), nullable=False)
    candidate_name = Column(String, nullable=False)
    first_pref_votes = Column(Integer, default=0)
    second_pref_votes = Column(Integer, default=0)
    total_votes = Column(Integer, default=0)
    transferred_votes = Column(Integer, default=0)

    # New field to store the quota for the round
    quota = Column(Float, default=0.0)

    candidate = relationship("Candidate", back_populates="round_results")