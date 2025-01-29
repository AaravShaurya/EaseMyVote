# test_main.py

import pytest
from fastapi.testclient import TestClient
from main import app, get_db, serializer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
from models import Voter, Candidate
import os
from unittest.mock import AsyncMock, patch
from cryptography.fernet import Fernet

# Set environment variables for testing
os.environ["SECRET_KEY"] = "test_secret_key"
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["EMAIL_PASSWORD"] = "dummy_password"

# Setup for test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency override
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)  # Create the test database

    # Insert test data
    with TestingSessionLocal() as db:
        # Add candidates
        candidate1 = Candidate(id=1, name="Candidate One", position="MOCC")
        candidate2 = Candidate(id=2, name="Candidate Two", position="MOCC")
        db.add_all([candidate1, candidate2])
        db.commit()

    yield TestClient(app)

    Base.metadata.drop_all(bind=engine)  # Clean up the test database

@pytest.fixture(scope="module")
def create_voter():
    # Create a voter for testing purposes
    with TestingSessionLocal() as db:
        voter = Voter(email="test_1.sias22@krea.ac.in", has_voted=False)
        db.add(voter)
        db.commit()
        yield voter

@patch("aiosmtplib.send", new_callable=AsyncMock)
def test_login(mock_send, client, create_voter):
    mock_send.return_value = None
    response = client.post("/login", data={"email": "test_1.sias22@krea.ac.in"})
    assert response.status_code == 200
    assert "Unable to verify email." not in response.text

def test_verify_email(client, create_voter):
    # Simulate email verification
    email = "test_1.sias22@krea.ac.in"
    token = serializer.dumps(email, salt="email-confirm")
    response = client.get(f"/verify-email?token={token}", follow_redirects=False)
    assert response.status_code == 303  # Should redirect after verification

def test_vote_submission(client, create_voter):
    # Simulate logging in
    client.post("/login", data={"email": "test_1.sias22@krea.ac.in"})

    # Simulate email verification
    email = "test_1.sias22@krea.ac.in"
    token = serializer.dumps(email, salt="email-confirm")
    client.get(f"/verify-email?token={token}", follow_redirects=False)

    # Accept rules
    client.post("/rules")

    # Submit a vote
    response = client.post("/vote", data={"first_pref": 1, "second_pref": 2}, follow_redirects=False)
    assert response.status_code == 303  # Should redirect to summary after vote submission

def test_summary(client, create_voter):
    # Simulate logging in
    client.post("/login", data={"email": "test_1.sias22@krea.ac.in"})

    # Simulate email verification
    email = "test_1.sias22@krea.ac.in"
    token = serializer.dumps(email, salt="email-confirm")
    client.get(f"/verify-email?token={token}")

    # Accept rules
    client.post("/rules")

    # Submit a vote
    client.post("/vote", data={"first_pref": 1, "second_pref": 2})

    # Now check the summary
    response = client.get("/summary")
    assert response.status_code == 200

    # Check that the summary page contains the candidate names
    assert "Candidate One" in response.text
    assert "Candidate Two" in response.text
