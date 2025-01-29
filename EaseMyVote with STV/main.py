# main.py

# Server Instructions:
# Run the server using:
# uvicorn main:app --reload
# Access the application at:
# http://127.0.0.1:8000
# If you encounter an "address in use" error, find the PID using:
# lsof -i tcp:8000
# Then kill the process using:
# kill -9 <PID>
# If you face a "database locked" issue with SQLite, check if any process is using the database:
# lsof | grep easemyvote.db

# main.py

import os
from dotenv import load_dotenv

ENV = os.getenv('ENV', 'production')

if ENV == 'testing':
    load_dotenv('.env.test')
else:
    load_dotenv('.env')

from config import ProductionConfig, TestingConfig

if ENV == 'testing':
    app_config = TestingConfig()
else:
    app_config = ProductionConfig()

from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import Base, SessionLocal, engine
from models import Voter, Vote, Candidate, RoundResult
from pydantic import EmailStr
from cryptography.fernet import Fernet
from itsdangerous import URLSafeTimedSerializer
import aiosmtplib
from email.message import EmailMessage
from jinja2 import Template
import datetime
from starlette.middleware.sessions import SessionMiddleware
import json
import logging
import secrets
import hashlib

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize app and templates
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Mount the static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    favicon_path = os.path.join('static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path)
    else:
        return Response(status_code=204)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

FERNET_KEY = app_config.FERNET_KEY
if not FERNET_KEY:
    raise ValueError("FERNET_KEY is not set in the configuration.")
fernet = Fernet(FERNET_KEY)

SECRET_KEY = app_config.SECRET_KEY
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set in the configuration.")
serializer = URLSafeTimedSerializer(SECRET_KEY)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie=app_config.SESSION_COOKIE,
    max_age=app_config.SESSION_MAX_AGE,
    https_only=app_config.HTTPS_ONLY,
    same_site=app_config.SAME_SITE,
)

EMAIL_HOST = app_config.EMAIL_HOST
EMAIL_PORT = app_config.EMAIL_PORT
EMAIL_USERNAME = app_config.EMAIL_USERNAME
EMAIL_PASSWORD = app_config.EMAIL_PASSWORD
if not EMAIL_PASSWORD:
    raise ValueError("EMAIL_PASSWORD is not set in the configuration.")

def recalculate_vote_tally(db: Session):
    """
    Recalculate and store the vote tallies for two winners using a quota-based IRV system.
    Key points:
      - If a candidate's total meets/exceeds the quota, they immediately become a winner,
        but the process continues to find a second winner.
      - Multiple candidates can be tied for last place and get eliminated simultaneously.
      - If only two candidates remain and neither meets the quota, the candidate with 
        the higher total wins the second seat (or a tie if they have the same total).
      - first_pref_votes and second_pref_votes record how many ballots list each candidate
        as #1 or #2, regardless of who actually receives the IRV allocation in that round.
      - total_votes is the actual IRV-allocated total for that round.
    """

    # Clear previous round results
    db.query(RoundResult).delete()
    db.commit()

    # Fetch all votes and candidates
    votes = db.query(Vote).all()
    all_candidates = db.query(Candidate).all()

    # Active candidates: those still in the running
    active_candidates = {candidate.id: candidate for candidate in all_candidates}

    # Keep track of winners (we want exactly 2 winners for this position)
    winners = []
    total_seats = 2  # This position can have 2 winners

    total_votes = len(votes)
    round_number = 1

    # Convert each voter's preferences (JSON) into lists
    vote_preferences = {}
    for vote in votes:
        preferences = json.loads(vote.preferences)
        prefs_list = []
        if preferences.get('first_pref'):
            prefs_list.append(preferences['first_pref'])
        if preferences.get('second_pref'):
            prefs_list.append(preferences['second_pref'])
        # Extend logic for 3rd/4th preferences if needed
        vote_preferences[vote.id] = prefs_list

    previous_round_totals = None
    previous_active_candidate_ids = None

    # Repeat rounds until we have 2 winners or no candidates remain
    while len(winners) < total_seats and len(active_candidates) > 0:
        logger.info(f"Starting round {round_number}")

        # Calculate quota for this round
        num_active_candidates = len(active_candidates)
        # Avoid division by zero if somehow no active candidates remain
        if num_active_candidates == 0:
            break

        quota = 1 + (total_votes / num_active_candidates)
        logger.info(f"Quota for round {round_number}: {quota}")

        # STEP 1: Raw tallies for first and second preferences (for record-keeping)
        first_pref_tallies = {cid: 0 for cid in active_candidates.keys()}
        second_pref_tallies = {cid: 0 for cid in active_candidates.keys()}

        for vote in votes:
            prefs = vote_preferences[vote.id]
            if len(prefs) > 0:
                first_candidate_id = prefs[0]
                if first_candidate_id in active_candidates:
                    first_pref_tallies[first_candidate_id] += 1
            if len(prefs) > 1:
                second_candidate_id = prefs[1]
                if second_candidate_id in active_candidates:
                    second_pref_tallies[second_candidate_id] += 1

        # STEP 2: Allocate votes under IRV logic
        current_round_totals = {cid: 0 for cid in active_candidates.keys()}

        for vote in votes:
            prefs = vote_preferences[vote.id]
            for candidate_id in prefs:
                if candidate_id in active_candidates:
                    current_round_totals[candidate_id] += 1
                    break
            # If no active candidate is found in that voter's preference, vote is exhausted

        # STEP 3: Store and log results
        for cid in list(active_candidates.keys()):
            total_for_candidate = current_round_totals[cid]
            transferred_votes = 0
            if previous_round_totals is not None and cid in previous_round_totals:
                transferred_votes = total_for_candidate - previous_round_totals[cid]

            round_result = RoundResult(
                round_number=round_number,
                candidate_id=cid,
                candidate_name=active_candidates[cid].name,
                first_pref_votes=first_pref_tallies[cid],
                second_pref_votes=second_pref_tallies[cid],
                total_votes=total_for_candidate,
                transferred_votes=transferred_votes if transferred_votes > 0 else 0,
                quota=quota
            )
            db.add(round_result)

            logger.info(
                f"Round {round_number}: Candidate '{active_candidates[cid].name}' (ID: {cid}) "
                f"first_pref={first_pref_tallies[cid]}, second_pref={second_pref_tallies[cid]}, "
                f"total={total_for_candidate}, transferred={transferred_votes}, quota={quota}"
            )

        db.commit()

        # STEP 4: Check if any candidate meets/exceeds the quota => they become a winner
        round_winners = []
        for cid, total_for_candidate in current_round_totals.items():
            if total_for_candidate >= quota:
                round_winners.append(cid)

        # If multiple candidates cross the quota in the same round,
        # they all become winners simultaneously (up to 2 seats).
        for cid in round_winners:
            if cid in active_candidates and cid not in winners:
                winners.append(cid)
                logger.info(
                    f"Candidate '{active_candidates[cid].name}' (ID: {cid}) "
                    f"has reached/exceeded quota with {current_round_totals[cid]} votes "
                    f"in round {round_number} and is declared a winner."
                )
                # Remove them from active so they do not accumulate more votes
                active_candidates.pop(cid)

        # If we have filled both seats, stop counting
        if len(winners) >= total_seats:
            break

        # Check the scenario: if exactly 2 candidates remain and we haven't filled 2 seats yet
        if len(active_candidates) == 2 and len(winners) < total_seats:
            cid_list = list(active_candidates.keys())
            c1, c2 = cid_list[0], cid_list[1]
            v1, v2 = current_round_totals[c1], current_round_totals[c2]

            # If neither meets quota, pick the one with higher votes to fill the seat
            if v1 == v2:
                logger.info(
                    f"Only two candidates remain (IDs: {c1}, {c2}), both tied at {v1} votes. "
                    "Election ends in a tie for the second winner."
                )
            else:
                # The one with the higher total is the second winner
                winner_id = c1 if v1 > v2 else c2
                winners.append(winner_id)
                logger.info(
                    f"Only two candidates remain. Second winner by higher vote count: "
                    f"'{active_candidates[winner_id].name}' with {current_round_totals[winner_id]} votes."
                )
            # After picking the second winner, we can end the process
            break

        # Detect if no changes from previous round (tie or deadlock)
        current_active_candidate_ids = set(active_candidates.keys())
        if (
            previous_round_totals == current_round_totals
            and previous_active_candidate_ids == current_active_candidate_ids
        ):
            logger.info(
                "No changes in vote totals and active candidates. "
                "Election ends with tie among remaining candidates."
            )
            break

        # Identify candidate(s) with the fewest votes and eliminate them all if there's more than 2 left
        if len(active_candidates) > 2:
            min_votes_in_round = min(current_round_totals[cid] for cid in active_candidates.keys())
            candidates_with_min_votes = [
                cid for cid in active_candidates.keys() if current_round_totals[cid] == min_votes_in_round
            ]

            if min_votes_in_round == 0:
                # Eliminate all candidates with zero votes
                for cid in candidates_with_min_votes:
                    logger.info(
                        f"Eliminating candidate '{active_candidates[cid].name}' (ID: {cid}) with zero votes"
                    )
                    active_candidates.pop(cid)
            else:
                # Eliminate ALL last-place candidates in a tie
                tied_names = [active_candidates[cid].name for cid in candidates_with_min_votes]
                logger.info(
                    f"Last-place tie among {tied_names} with {min_votes_in_round} votes. "
                    "Eliminating all of them simultaneously."
                )
                for cid in candidates_with_min_votes:
                    active_candidates.pop(cid)

        # Update for next round
        previous_round_totals = current_round_totals.copy()
        previous_active_candidate_ids = set(active_candidates.keys())
        round_number += 1

    # --- STEP 5: After the loop, see if we have 2 winners. If not, handle final scenarios. ---
    if len(winners) < total_seats:
        # If we still have active candidates, find the top (remaining) candidate by votes
        # or handle ties. Typically, you'd do a final round's "max" check:
        if len(active_candidates) > 0 and previous_round_totals:
            # We only do this if we haven't just done it in the loop
            max_votes_current = max(previous_round_totals[cid] for cid in active_candidates.keys())
            top_candidates = [
                cid for cid in active_candidates.keys()
                if previous_round_totals[cid] == max_votes_current
            ]
            if len(top_candidates) == 1:
                winners.append(top_candidates[0])
                logger.info(
                    f"Filling final seat by highest votes (no quota reached): "
                    f"{active_candidates[top_candidates[0]].name} with {max_votes_current} votes"
                )
            else:
                tied_names = [active_candidates[cid].name for cid in top_candidates]
                logger.info(
                    f"No clear single candidate for final seat. Tied at {max_votes_current} votes: "
                    f"{', '.join(tied_names)}"
                )
        else:
            logger.info("No active candidates remain to fill the remaining seat(s).")

    # Log final winners
    if winners:
        # Retrieve names for logging
        winner_names = []
        for wid in winners:
            # It's possible a winner was found after being removed from active_candidates
            # so refer back to all_candidates if not in active_candidates
            winner_candidate = None
            if wid in active_candidates:
                winner_candidate = active_candidates[wid]
            else:
                for cand in all_candidates:
                    if cand.id == wid:
                        winner_candidate = cand
                        break

            if winner_candidate:
                winner_names.append(winner_candidate.name)

        if len(winner_names) == 1:
            logger.info(f"Final result: 1 winner -> {winner_names[0]}")
        elif len(winner_names) >= 2:
            logger.info(f"Final result: 2 winners -> {winner_names[0]} and {winner_names[1]}")
        else:
            logger.info("No winners could be determined.")
    else:
        logger.info("No winners declared.")

    logger.info("Vote tallies recalculated and stored in RoundResult table.")

# Routes

@app.get("/", response_class=HTMLResponse)
def read_login(request: Request):
    return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": None})

@app.post("/login")
async def login(
    request: Request,
    email: EmailStr = Form(...),
    db: Session = Depends(get_db)
):
    email = email.lower().strip()  # Normalize email
    logger.info(f"Email entered: {email}")

    # Validate email
    if not all(component in email for component in ["sias", "krea"]):
        logger.warning(f"Email validation failed for: {email}")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Unable to verify email."})

    # Check if voter exists
    voter = db.query(Voter).filter(Voter.email == email).first()
    if voter:
        # Check if voter has voted in the last 6 months
        if voter.has_voted:
            if voter.voted_at:
                six_months_ago = datetime.datetime.utcnow() - datetime.timedelta(days=180)
                if voter.voted_at >= six_months_ago:
                    logger.info(f"Voter {email} has already voted in the last 6 months.")
                    return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "You have already voted in the last 6 months."})
                else:
                    # Reset voter status
                    voter.has_voted = False
                    voter.is_verified = False
                    try:
                        db.commit()
                        logger.info(f"Voter {email} voting status reset.")
                    except Exception as e:
                        db.rollback()
                        logger.error(f"Database commit failed: {e}")
                        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Database error."})
            else:
                # If voted_at is None, reset voting status
                voter.has_voted = False
                voter.is_verified = False
                try:
                    db.commit()
                    logger.info(f"Voter {email} voting status reset.")
                except Exception as e:
                    db.rollback()
                    logger.error(f"Database commit failed: {e}")
                    return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Database error."})
    else:
        logger.warning(f"Voter with email {email} does not exist in the database.")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Unable to verify email."})

    # Generate a token for email verification
    token = serializer.dumps(email, salt="email-confirm")

    # Create a verification link
    verification_link = f"http://127.0.0.1:8000/verify-email?token={token}"

    # Render the email template
    template_path = "verification_email.html"
    try:
        with open(os.path.join("templates", template_path)) as f:
            template = Template(f.read())
    except FileNotFoundError:
        logger.error(f"Email template '{template_path}' not found.")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Email template missing."})

    email_body = template.render(email=email, verification_link=verification_link)

    # Prepare the email message
    message = EmailMessage()
    message["From"] = EMAIL_USERNAME
    message["To"] = email
    message["Subject"] = "EaseMyVote Email Verification"
    message.set_content(email_body, subtype="html")

    # Send the verification email asynchronously
    try:
        await aiosmtplib.send(
            message,
            hostname=EMAIL_HOST,
            port=EMAIL_PORT,
            start_tls=True,
            username=EMAIL_USERNAME,
            password=EMAIL_PASSWORD,
        )
        logger.info(f"Verification email sent to {email}.")
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Unable to send verification email."})

    return templates.TemplateResponse("email_sent.html", {"request": request})

@app.get("/verify-email", response_class=HTMLResponse)
def verify_email(request: Request, token: str, db: Session = Depends(get_db)):
    """
    Verifies the email of the user and prevents multiple voting by checking if they
    have already voted.

    Args:
        request (Request): The request object.
        token (str): The email verification token.
        db (Session): The database session.

    Returns:
        RedirectResponse: Redirects to the rules page if successful, or returns an error if invalid.
    """
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)
        logger.info(f"Email verified: {email}")
    except (SignatureExpired, BadSignature, BadTimeSignature) as e:
        logger.warning(f"Email verification failed: {e}")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "The verification link is invalid or has expired."})

    # Fetch the voter from the database
    voter = db.query(Voter).filter(Voter.email == email).first()
    if not voter:
        logger.warning(f"Voter with email {email} not found during verification.")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Unable to verify email."})

    # Check if the voter has already voted
    if voter.has_voted:
        logger.info(f"Voter {email} has already voted and cannot vote again.")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "You have already voted and cannot vote again."})

    # Mark voter as verified
    voter.is_verified = True

    # Generate and store encrypted_id if not already set
    if not voter.encrypted_id:
        encrypted_voter_id = fernet.encrypt(str(voter.id).encode()).decode()
        voter.encrypted_id = encrypted_voter_id

    try:
        db.commit()
        logger.info(f"Voter {email} has been verified.")
    except Exception as e:
        db.rollback()
        logger.error(f"Database commit failed: {e}")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Database error during verification."})

    # Generate a random voting token and store it in session
    voting_token = secrets.token_urlsafe(32)
    request.session['voting_token'] = voting_token

    # Store data in session
    request.session['user_email'] = email
    request.session['rules_read'] = False

    # Redirect to the rules page
    return RedirectResponse(url="/rules", status_code=303)

@app.get("/rules", response_class=HTMLResponse)
def show_rules(request: Request):
    email = request.session.get('user_email')
    if not email:
        logger.warning("No user_email in session. Redirecting to login.")
        return RedirectResponse(url="/")
    return templates.TemplateResponse("Rules_EMV.html", {"request": request})

@app.post("/rules")
def accept_rules(request: Request):
    email = request.session.get('user_email')
    if not email:
        logger.warning("No user_email in session during rules acceptance. Redirecting to login.")
        return RedirectResponse(url="/", status_code=303)

    request.session['rules_read'] = True
    logger.info(f"User {email} accepted the rules.")
    return RedirectResponse(url="/voting", status_code=303)

@app.get("/voting", response_class=HTMLResponse)
def show_voting_page(request: Request, db: Session = Depends(get_db)):
    """
    Displays the voting page. Allows access to users who have already voted if they are returning from the summary page.
    Args:
        request (Request): The request object.
        db (Session): The database session.
    Returns:
        HTMLResponse: Renders the voting page template.
    """
    email = request.session.get('user_email')
    rules_read = request.session.get('rules_read')

    if not email:
        logger.warning("No user_email in session when accessing voting page. Redirecting to login.")
        return RedirectResponse(url="/")
    if not rules_read:
        logger.info("Rules not accepted yet. Redirecting to rules page.")
        return RedirectResponse(url="/rules")

    # Fetch the voter from the database
    voter = db.query(Voter).filter(Voter.email == email).first()
    if not voter:
        logger.warning(f"Voter with email {email} not found when accessing voting page.")
        return RedirectResponse(url="/")

    # Check if the voter has already voted, but allow them to go back and change their vote
    if voter.has_voted:
        # Allow the user to return to the voting page from the summary page to change their vote
        logger.info(f"Voter {email} is returning to the voting page to modify their vote.")
        # Note: We will allow access even if they have voted, so no error message is shown here.

    # Define the position to display
    position = "MOCC"

    try:
        candidates = db.query(Candidate).filter(func.lower(Candidate.position) == position.lower()).all()
    except Exception as e:
        logger.error(f"Error fetching candidates: {e}")
        raise HTTPException(status_code=500, detail="Error fetching candidates.")

    candidate_names = [candidate.name for candidate in candidates]
    logger.info(f"Candidates for position '{position}': {candidate_names}")

    return templates.TemplateResponse("Voting_EMV.html", {"request": request, "candidates": candidates, "position": position})

@app.post("/vote")
def submit_vote(
    request: Request,
    first_pref: int = Form(...),
    second_pref: int = Form(...),
    db: Session = Depends(get_db)
):
    """
    Submits or updates the user's vote. Allows users to change their vote if they return from the summary page.
    Args:
        request (Request): The request object.
        first_pref (int): The first preference candidate ID.
        second_pref (int): The second preference candidate ID.
        db (Session): The database session.
    Returns:
        RedirectResponse: Redirects to the summary page after submission.
    """
    email = request.session.get('user_email')
    if not email:
        logger.warning("Email missing in session during vote submission.")
        raise HTTPException(status_code=400, detail="Email missing")

    # Fetch the voter from the database
    voter = db.query(Voter).filter(Voter.email == email).first()
    if not voter:
        logger.warning(f"Voter with email {email} not found during vote submission.")
        return templates.TemplateResponse("Login_EMV.html", {"request": request, "error": "Unable to verify email."})

    # Get the voting token from session
    voting_token = request.session.get('voting_token')
    if not voting_token:
        logger.warning("Voting token missing in session during vote submission.")
        raise HTTPException(status_code=400, detail="Voting token missing")

    # Generate a hashed token using SHA-256
    hashed_voter_token = hashlib.sha256(voting_token.encode()).hexdigest()

    # Check if a vote already exists for this voter
    existing_vote = db.query(Vote).filter(Vote.encrypted_voter_id == hashed_voter_token).first()

    preferences = {
        "first_pref": first_pref,
        "second_pref": second_pref
    }

    try:
        if existing_vote:
            # Update the existing vote
            existing_vote.preferences = json.dumps(preferences)
            logger.info(f"Updated vote for voter {email}.")
        else:
            # Create a new vote
            vote = Vote(
                encrypted_voter_id=hashed_voter_token,
                preferences=json.dumps(preferences)
            )
            db.add(vote)
            logger.info(f"Created new vote for voter {email}.")

        voter.has_voted = True
        voter.voted_at = datetime.datetime.utcnow()
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Database commit failed during vote submission: {e}")
        raise HTTPException(status_code=500, detail="Database error during vote submission.")

    # Recalculate and update vote tallies
    recalculate_vote_tally(db)

    logger.info(f"Vote submitted by {email}.")

    return RedirectResponse(url="/summary", status_code=303)

@app.get("/summary", response_class=HTMLResponse)
def show_summary(request: Request, db: Session = Depends(get_db)):
    email = request.session.get('user_email')
    if not email:
        logger.warning("No user_email in session when accessing summary page. Redirecting to login.")
        return RedirectResponse(url="/")

    # Get the voting token from session
    voting_token = request.session.get('voting_token')
    if not voting_token:
        logger.warning("Voting token missing in session when accessing summary.")
        return RedirectResponse(url="/")

    # Generate a hashed token using SHA-256
    hashed_voter_token = hashlib.sha256(voting_token.encode()).hexdigest()

    # Fetch the vote using hashed_voter_token
    vote = db.query(Vote).filter(Vote.encrypted_voter_id == hashed_voter_token).first()
    if not vote:
        logger.warning(f"Vote not found for voter {email} when fetching summary.")
        return RedirectResponse(url="/")
    preferences = json.loads(vote.preferences)

    first_pref_candidate = db.query(Candidate).filter(Candidate.id == preferences['first_pref']).first()
    second_pref_candidate = db.query(Candidate).filter(Candidate.id == preferences['second_pref']).first()

    preferences_display = {
        "first_pref": first_pref_candidate.name if first_pref_candidate else "N/A",
        "second_pref": second_pref_candidate.name if second_pref_candidate else "N/A"
    }

    logger.info(f"Summary for {email}: {preferences_display}")

    return templates.TemplateResponse("Summary_EMV.html", {"request": request, "preferences": preferences_display})

@app.get("/thankyou", response_class=HTMLResponse)
async def thank_you(request: Request, db: Session = Depends(get_db)):
    """
    Display the thank you page after the user has submitted their vote.
    Additionally, send a confirmation email to the voter confirming that their vote has been cast.

    Args:
        request (Request): FastAPI Request object.
        db (Session): Database session for retrieving user information.

    Returns:
        HTMLResponse: Renders the Thank You page template.
    """
    email = request.session.get('user_email')
    if not email:
        logger.warning("No user_email in session when accessing thank you page. Redirecting to login.")
        return RedirectResponse(url="/")

    # Send confirmation email
    subject = "EaseMyVote: Vote Confirmation"
    message = f"Dear voter, your vote has been successfully recorded. Thank you for voting in EaseMyVote!"

    email_message = EmailMessage()
    email_message["From"] = EMAIL_USERNAME
    email_message["To"] = email
    email_message["Subject"] = subject
    email_message.set_content(message)

    try:
        await aiosmtplib.send(
            email_message,
            hostname=EMAIL_HOST,
            port=EMAIL_PORT,
            start_tls=True,
            username=EMAIL_USERNAME,
            password=EMAIL_PASSWORD,
        )
        logger.info(f"Confirmation email sent to {email}.")
    except Exception as e:
        logger.error(f"Failed to send confirmation email: {e}")

    # Clear the voting token from the session
    request.session.pop('voting_token', None)

    return templates.TemplateResponse("ThankYou_EMV.html", {"request": request})
        
#         if len(candidate_ids) == 1:
#             round_info["winner"] = candidate_names[candidate_ids[0]]
#             return {"rounds": rounds, "winner": candidate_names[candidate_ids[0]]}
        
