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
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature, BadTimeSignature
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
    """
    Serve the EaseMyVote favicon from local /static folder.
    """
    favicon_path = os.path.join('static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path)
    else:
        return Response(status_code=204)

# Create database tables if needed
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

# Hardcoded number of seats per position
SEATS_PER_POSITION = {
    "MOCC": 2,
    "Chair": 2,
    "MOF": 3,
    "IC": 2
}

def recalculate_vote_tally(db: Session):
    """
    Recalculate and store IRV results for each position, with:
      quota = 1 + ( total_votes / (1 + seat_count) )
    
    Weighted second preferences start after Round 1.
    The number of seats for each position is hardcoded in SEATS_PER_POSITION.

    ABSTAIN logic:
      - If a voter picks "ABSTAIN" as first_pref, we skip that ballot entirely
        but increment 'abstain_first_pref' count for the round.
      - If a voter picks "ABSTAIN" as second_pref, we never count that as a valid second choice.
    """

    # Clear ALL existing round results
    db.query(RoundResult).delete()
    db.commit()

    all_candidates = db.query(Candidate).all()
    all_votes = db.query(Vote).all()

    # Group candidates by position
    candidates_by_position = {}
    for cand in all_candidates:
        candidates_by_position.setdefault(cand.position, []).append(cand)

    # Process each position independently
    for position_name, seat_count in SEATS_PER_POSITION.items():
        position_candidates = candidates_by_position.get(position_name, [])
        if not position_candidates:
            logger.info(f"No candidates found for position='{position_name}'. Skipping.")
            continue

        # Map candidate.id -> candidate
        active_candidates = {c.id: c for c in position_candidates}

        # Filter votes relevant to this position
        relevant_ids = set(active_candidates.keys())
        position_votes = []
        for vote in all_votes:
            prefs = json.loads(vote.preferences)
            # If either first or second pref is in relevant_ids, we consider it
            if prefs.get("first_pref") in relevant_ids or prefs.get("second_pref") in relevant_ids:
                position_votes.append(vote)

        total_votes = len(position_votes)
        if total_votes == 0:
            logger.info(f"No votes for position='{position_name}'. Skipping.")
            continue

        # Quota formula: 1 + ( total_votes / (1 + seat_count) )
        quota = 1 + (total_votes / (1 + seat_count))
        logger.info(
            f"\n--- Starting IRV for '{position_name}' with {seat_count} seat(s). "
            f"{len(position_candidates)} candidate(s), {total_votes} vote(s). "
            f"Quota={quota:.3f} ---"
        )

        # Weighted second preference
        weight = (total_votes - quota) / total_votes if total_votes != 0 else 0
        logger.info(f"Second preference weight for '{position_name}': {weight:.3f}")

        # Convert each vote's preferences
        vote_preferences = {}
        for v in position_votes:
            prefs_json = json.loads(v.preferences)
            # We store them as strings; "ABSTAIN" is recognized
            pref_list = []
            if "first_pref" in prefs_json:
                pref_list.append(str(prefs_json["first_pref"]))
            if "second_pref" in prefs_json:
                pref_list.append(str(prefs_json["second_pref"]))
            vote_preferences[v.id] = pref_list

        winners = []
        round_number = 1
        previous_round_totals = None
        previous_active_ids = None

        while len(winners) < seat_count and active_candidates:
            logger.info(
                f"Position='{position_name}', Round={round_number}, seats to fill={seat_count - len(winners)}"
            )

            # Step 1: Tally raw #1 and #2, ignoring "ABSTAIN" for counting candidates
            first_pref_counts = {cid: 0 for cid in active_candidates}
            second_pref_counts = {cid: 0.0 for cid in active_candidates}

            # track how many ABSTAIN for first preference
            abstain_first_pref_count = 0

            for v_id, prefs in vote_preferences.items():
                # If no preferences or first_pref is ABSTAIN => skip entirely
                if len(prefs) == 0:
                    continue

                if prefs[0].upper() == "ABSTAIN":
                    # This ballot is totally skipped from counting
                    abstain_first_pref_count += 1
                    continue

                # Otherwise, if the first pref is in active_candidates
                try:
                    first_id = int(prefs[0])
                    if first_id in active_candidates:
                        first_pref_counts[first_id] += 1
                except ValueError:
                    continue

                # If there's a second pref and it's not "ABSTAIN"
                if len(prefs) > 1 and prefs[1].upper() != "ABSTAIN":
                    try:
                        second_id = int(prefs[1])
                        if second_id in active_candidates:
                            second_pref_counts[second_id] += 1
                    except ValueError:
                        pass

            # Step 2: Weighted IRV allocation
            current_totals = {cid: 0.0 for cid in active_candidates}
            for v_id, prefs in vote_preferences.items():
                if len(prefs) == 0 or prefs[0].upper() == "ABSTAIN":
                    continue

                if round_number == 1:
                    # Standard IRV for first round
                    for c_str in prefs:
                        if c_str.upper() == "ABSTAIN":
                            break
                        try:
                            c_id = int(c_str)
                            if c_id in active_candidates:
                                current_totals[c_id] += 1.0
                                break
                        except ValueError:
                            continue
                else:
                    # Weighted approach from round 2 onward
                    assigned = False
                    if len(prefs) > 0 and prefs[0].upper() != "ABSTAIN":
                        try:
                            first_id = int(prefs[0])
                            if first_id in active_candidates:
                                current_totals[first_id] += 1.0
                                assigned = True
                        except ValueError:
                            pass
                    if not assigned and len(prefs) > 1:
                        if prefs[1].upper() == "ABSTAIN":
                            continue
                        try:
                            second_id = int(prefs[1])
                            if second_id in active_candidates:
                                current_totals[second_id] += weight
                        except ValueError:
                            pass

            # Step 3: Store round results
            for cid in list(active_candidates.keys()):
                total_val = current_totals[cid]
                transferred = 0.0
                if previous_round_totals and cid in previous_round_totals:
                    transferred = total_val - previous_round_totals[cid]

                rr = RoundResult(
                    round_number=round_number,
                    candidate_id=cid,
                    candidate_name=active_candidates[cid].name,
                    first_pref_votes=first_pref_counts[cid],
                    second_pref_votes=second_pref_counts[cid],
                    total_votes=total_val,
                    transferred_votes=transferred,
                    quota=quota,
                    position=position_name,
                    abstain_first_pref=abstain_first_pref_count
                )
                db.add(rr)

                logger.info(
                    f"Pos='{position_name}', Round {round_number}, Cand='{active_candidates[cid].name}' -> "
                    f"first_pref={first_pref_counts[cid]}, second_pref={second_pref_counts[cid]}, "
                    f"total={total_val:.2f}, transferred={transferred:.2f}, "
                    f"abstain_first_pref={abstain_first_pref_count}, quota={quota:.2f}"
                )

            db.commit()

            # Step 4: Check for winners
            round_winners = [
                cid for cid in active_candidates if current_totals[cid] >= quota
            ]
            for cid in round_winners:
                if cid not in winners:
                    winners.append(cid)
                    logger.info(
                        f"Candidate '{active_candidates[cid].name}' for '{position_name}' "
                        f"meets/exceeds quota ({current_totals[cid]:.2f} >= {quota:.2f}) -> declared winner."
                    )
                    active_candidates.pop(cid)

            if len(winners) >= seat_count:
                break

            # If only 2 remain
            if len(active_candidates) == 2 and len(winners) < seat_count:
                cids = list(active_candidates.keys())
                c1, c2 = cids[0], cids[1]
                v1, v2 = current_totals[c1], current_totals[c2]
                seats_left = seat_count - len(winners)

                if seats_left > 1:
                    logger.info(
                        f"Only 2 candidates remain for '{position_name}' with {seats_left} seats left => both winners."
                    )
                    winners.extend([c1, c2])
                else:
                    if abs(v1 - v2) < 1e-9:
                        logger.info(
                            f"Tie for last seat in '{position_name}' between {c1} and {c2} with {v1:.2f} votes each."
                        )
                    else:
                        final_winner = c1 if v1 > v2 else c2
                        winners.append(final_winner)
                        logger.info(
                            f"Final seat in '{position_name}' -> candidate {final_winner} by higher vote ({max(v1,v2):.2f})."
                        )
                break

            # If no changes => tie
            current_ids = set(active_candidates.keys())
            if (
                previous_round_totals == current_totals
                and previous_active_ids == current_ids
            ):
                logger.info(f"No changes in '{position_name}' from previous round. Election tied.")
                break

            # Eliminate last place if more than seats_left + 1 remain
            if len(active_candidates) > (seat_count - len(winners) + 1):
                min_val = min(current_totals[cid] for cid in active_candidates)
                last_place = [
                    cid for cid in active_candidates
                    if abs(current_totals[cid] - min_val) < 1e-9
                ]
                if abs(min_val) < 1e-9:
                    logger.info(
                        f"Eliminating candidate(s) with 0 votes in '{position_name}': "
                        + ", ".join(active_candidates[c].name for c in last_place)
                    )
                    for c in last_place:
                        active_candidates.pop(c)
                else:
                    logger.info(
                        f"Eliminating last-place tie (value={min_val:.2f}) in '{position_name}': "
                        + ", ".join(active_candidates[c].name for c in last_place)
                    )
                    for c in last_place:
                        active_candidates.pop(c)

            previous_round_totals = current_totals.copy()
            previous_active_ids = current_ids
            round_number += 1

        # If seats remain unfilled
        if len(winners) < seat_count and active_candidates:
            final_vals = previous_round_totals
            best_val = max(final_vals[c] for c in active_candidates)
            top_cands = [
                c for c in active_candidates
                if abs(final_vals[c] - best_val) < 1e-9
            ]
            needed = seat_count - len(winners)
            if len(top_cands) == 1:
                w = top_cands[0]
                winners.append(w)
                logger.info(
                    f"Filling final seat(s) for '{position_name}' => candidate {w} with {best_val:.2f} votes"
                )
            else:
                logger.info(
                    f"Tie for final seat(s) in '{position_name}': {', '.join(str(tc) for tc in top_cands)}"
                )

        logger.info(f"Winners for position='{position_name}': {winners}")
        for cid in winners:
            cand = next((c for c in position_candidates if c.id == cid), None)
            if cand:
                logger.info(f" -> {cand.name}")

        logger.info(f"Finished IRV for '{position_name}'.\n")

    logger.info("All positions processed. IRV results stored in RoundResult.")

# -------------- ROUTE FOR THE LOGIN PAGE --------------
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


# @app.get("/results", response_class=HTMLResponse)
# def get_results(request: Request, db: Session = Depends(get_db)):
#     votes = db.query(Vote).all()
#     all_preferences = [json.loads(vote.preferences) for vote in votes]

#     # Candidates list from the database
#     candidate_objs = db.query(Candidate).all()
#     candidates = {str(candidate.id): candidate.name for candidate in candidate_objs}
#     winner_id = instant_runoff_voting(all_preferences, list(candidates.keys()))
#     winner_name = candidates.get(str(winner_id), "No winner")

#     return templates.TemplateResponse("results.html", {"request": request, "winner": winner_name})

#@app.get("/runoff-voting/{position}")
#def run_off_voting(position: str, db: Session = Depends(get_db)):
   # winner = instant_runoff_voting(db, position)
   # return {"winner": winner}

# def instant_runoff_voting(db: Session, position: str):
#     candidates = db.query(Candidate).filter(Candidate.position == position).all()
#     candidate_ids = [str(candidate.id) for candidate in candidates]
#     candidate_names = {str(candidate.id): candidate.name for candidate in candidates}
    
#     votes = db.query(Vote).filter(Vote.preferences.isnot(None)).all()
#     vote_data = [json.loads(vote.preferences) for vote in votes]

#     rounds = []
#     round_number = 1
    
#     while True:
#         counts = defaultdict(int)
        
#         # Count votes based on first preferences
#         for vote in vote_data:
#             if 'first_pref' in vote and vote['first_pref'] in candidate_ids:
#                 counts[vote['first_pref']] += 1

#         total_votes = sum(counts.values())
#         round_info = {
#             "round": round_number,
#             "counts": {candidate_names[cid]: count for cid, count in counts.items()},
#         }
#         rounds.append(round_info)

#         # Check for a winner
#         for candidate_id, count in counts.items():
#             if count > total_votes / 2:
#                 round_info["winner"] = candidate_names[candidate_id]
#                 return {"rounds": rounds, "winner": candidate_names[candidate_id]}

#         if not counts:
#             return {"rounds": rounds, "winner": "No candidates left"}

#         # Eliminate candidate with the fewest votes
#         least_votes_candidate = min(counts, key=counts.get)
#         candidate_ids.remove(least_votes_candidate)
#         round_info["eliminated"] = candidate_names[least_votes_candidate]

#         # Remove eliminated candidate from votes and promote second preferences
#         for vote in vote_data:
#             if 'first_pref' in vote and vote['first_pref'] == least_votes_candidate:
#                 vote['first_pref'] = vote.get('second_pref', None)
#                 vote['second_pref'] = None

#         round_number += 1
        
#         if len(candidate_ids) == 1:
#             round_info["winner"] = candidate_names[candidate_ids[0]]
#             return {"rounds": rounds, "winner": candidate_names[candidate_ids[0]]}
        