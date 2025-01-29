# add_candidates.py

import os
import sys
from dotenv import load_dotenv

# Load environment variables before importing database
ENV = os.getenv('ENV', 'production')

if ENV == 'testing':
    load_dotenv('.env.test')
else:
    load_dotenv('.env')

# Add the project root directory to sys.path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)

from database import Base, SessionLocal, engine
import models  # Import models to register them with Base

# Ensure all models are registered before creating tables
Base.metadata.create_all(bind=engine)

db = SessionLocal()

# Optional: Clear existing candidates before adding new ones
# Uncomment the following lines if you want to remove existing candidates
# db.query(models.Candidate).delete()
# db.commit()

# Add candidates with consistent position names
candidates = [
    models.Candidate(name="Ukta", position="MOCC"),
    models.Candidate(name="Arsh", position="MOCC"),
    models.Candidate(name="Viney", position="MOCC"),
    models.Candidate(name="Aarav",position="MOCC"),
]

db.add_all(candidates)
db.commit()
db.close()

print("Candidates added successfully.")
