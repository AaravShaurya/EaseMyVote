# import_voters.py

import pandas as pd
import os
import traceback
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Voter  # Import models to register them with Base
from database import Base  # Import the shared Base

# Initialize the database (if not already initialized)
Base.metadata.create_all(bind=engine)

def read_voter_data(excel_file_path):
    try:
        df = pd.read_excel(excel_file_path, engine='openpyxl')
        return df
    except FileNotFoundError:
        print(f"Error: The file '{excel_file_path}' does not exist.")
        exit(1)
    except Exception as e:
        print(f"An error occurred while reading the Excel file: {e}")
        exit(1)

def import_voters(df):
    db = SessionLocal()
    try:
        required_columns = ['Email ID', 'Name']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Column '{col}' is missing from the Excel file.")

        for index, row in df.iterrows():
            email = str(row['Email ID']).strip().lower()
            name = str(row['Name']).strip()
            if not email or not name:
                print(f"Row {index} is missing email or name. Skipping.")
                continue
            # Check if voter already exists
            voter = db.query(Voter).filter(Voter.email == email).first()
            if not voter:
                # Only add voters who meet the email criteria
                if 'sias' in email and 'krea' in email:
                    voter = Voter(email=email, is_verified=False, has_voted=False, encrypted_id=None)
                    db.add(voter)
            else:
                print(f"Voter with email {email} already exists. Skipping.")
        db.commit()
        print("Voter data imported successfully.")
    except Exception as e:
        print(f"An error occurred during import: {e}")
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    # Path to your Excel file
    excel_file_path = 'SIAS22-25Data.xlsx'  # Update with your actual file path

    # Check if the file exists
    if not os.path.isfile(excel_file_path):
        print(f"Error: File not found: {excel_file_path}")
        exit(1)

    print("read voter data")
    df = read_voter_data(excel_file_path)
    print("before import voter")
    import_voters(df)
