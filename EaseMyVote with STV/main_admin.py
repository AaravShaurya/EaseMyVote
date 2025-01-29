from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Candidate, Voter  # Ensure Voter model is created
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import httpx
import os

# Load environment variables from .env file (or .env.test if ENV=testing)
load_dotenv()

app = FastAPI()

# Set up sessions middleware
app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

# Load templates
templates = Jinja2Templates(directory="templates")

# Mount the static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# OAuth client credentials
client_id = os.getenv("GOOGLE_CLIENT_ID")
client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

# Safely load ALLOWED_EMAILS (comma-separated list) from environment
allowed_emails_str = os.getenv("ALLOWED_EMAILS", "")
if allowed_emails_str:
    allowed_emails = allowed_emails_str.split(",")
else:
    allowed_emails = []

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/auth/google")
async def login_with_google():
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return RedirectResponse(
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope=email profile openid"
    )

@app.get("/auth/google/callback")
async def google_callback(request: Request, code: str):
    redirect_uri = "http://localhost:8000/auth/google/callback"
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        tokens = response.json()
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        user_info_response = await client.get(
            user_info_url,
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        user_info = user_info_response.json()

    user_email = user_info.get('email')

    if user_email in allowed_emails:
        request.session['user'] = user_info
        return RedirectResponse(url="/dashboard")
    else:
        return templates.TemplateResponse("access_denied.html", {"request": request})

@app.get("/dashboard")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = request.session.get('user')

    if user:
        user_email = user.get('email')

        # Check if the user's email is in the allowed emails list
        if user_email in allowed_emails:
            # Example usage: if your Candidate model has 'vote_tally', or adapt to your actual schema
            candidates = db.query(Candidate).all()
            candidate_data = [
                {
                    "name": candidate.name,
                    # If 'vote_tally' is removed from your schema, remove or replace this line
                    "vote_tally": getattr(candidate, "vote_tally", 0)
                }
                for candidate in candidates
            ]
            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "user": user,
                "candidate_data": candidate_data
            })

    # If user is not authenticated or not allowed, redirect to access denied or home
    return RedirectResponse("/access_denied")

@app.get("/batch-data")
async def batch_data(request: Request, db: Session = Depends(get_db)):
    user = request.session.get('user')

    if user:
        user_email = user.get('email')

        # Check if the user's email is in the allowed emails list
        if user_email in allowed_emails:
            return templates.TemplateResponse("batch_data_EVM.html", {"request": request})

    return RedirectResponse("/access_denied")

@app.get("/get_voter_list")
async def get_voter_list(db: Session = Depends(get_db)):
    """
    Fetches the voter list with verification and voting status.
    """
    voters = db.query(Voter).all()
    voter_list = [{
        "email": voter.email,
        "is_verified": voter.is_verified,
        "has_voted": voter.has_voted
    } for voter in voters]

    return JSONResponse(voter_list)

@app.get("/api/votes")
async def get_votes(db: Session = Depends(get_db)):
    """
    Returns the current vote tallies for all candidates.
    """
    candidates = db.query(Candidate).all()
    # If 'vote_tally' is not a real column, adapt accordingly
    return [{"name": candidate.name, "vote_tally": getattr(candidate, "vote_tally", 0)} for candidate in candidates]

@app.get("/access_denied", response_class=HTMLResponse)
async def access_denied(request: Request):
    return templates.TemplateResponse("access_denied.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)

