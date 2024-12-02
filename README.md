# COMP350-Team-Infinity
## 5 Sentence Summary

Introduction: The annual student government elections at our university have traditionally been conducted using Google Forms.

Related Work: Existing election systems like Election Buddy offer similar functionalities but are not suitable for our university’s budget, Google Forms is another commonly used tool.

Problem Statement: The use of Google Forms for student elections resulted in vulnerabilities such as potential breaches of voter anonymity, difficulty in preventing multiple submissions, and challenges in efficiently managing and verifying results.

Solution Proposal: We propose developing a dedicated election software system that integrates with the university’s ID system, ensuring secure, anonymous voting, preventing double voting, and providing real-time, transparent results.

Validation: The success of this system will be measured by its ability to eliminate the issues previously encountered with Google Forms, particularly in terms of security, anonymity, and result management, leading to its adoption for future elections at the university.

## Sequence Diagram 
(Image in docs folder labelled (Sequence Diagram.jpg))

### Actors: User (Voter), Admin, System.

### Processes:

User Login: The user accesses the login page and inputs their credentials (limited to specific IDs).

System Authentication: The system verifies user credentials.

Vote Casting: User selects their voting preferences.

Anonymity and Encryption: The system encrypts the vote to ensure anonymity.

Vote Submission: The user submits their vote.

Vote Storage: The system securely stores the encrypted vote.

Admin Access: Admin logs in to manage the election process, such as populating candidates.

Results Compilation: After voting ends, the system compiles the results.

Transparency Check: The system displays results publicly (without compromising individual votes). 

Double Voting Safeguard: System checks for and prevents any double-voting attempts. 

Confirmation: System sends an optional confirmation of the vote being successfully cast to the user.

## EaseMyVote Setup Guide

This guide will help you set up the EaseMyVote project on your local machine.

### Prerequisites

Ensure you have the following installed:

- Python 3.x
- Virtual Environment (`venv`)

### Steps to Set Up

#### 1. Create and Activate Virtual Environment

Clone the repository:
``` git clone https://github.com/your-username/ease-my-vote.git ```

Then enter the 'final' folder and do the following. All actions will be performed within the 'final' folder:

First, create and activate a virtual environment within your directory using the terminal:

```bash
python -m venv venv
source venv/bin/activate  # For Linux/Mac
# .\venv\Scripts\activate  # For Windows
```

#### 2. Install Dependencies
Once the virtual environment is activated, install the required packages within your directory using the terminal:

```
pip install -r requirements_main.txt
```

#### 3. Run Database and Import Scripts
Next, initialize the database and import the voters and candidates within your directory using the terminal:

```
# Run the database setup
python database.py

# Run the models script
python models.py

# Import voters from an Excel or CSV file
python import_voters.py

# Add candidates to the database
python add_candidates.py
```

#### 4. Set Environment Variables
You will need to set several environment variables for encryption keys and email handling.

1. Generate the FERNET_KEY using the provided script within your directory using the terminal:
```
python generate_fernet_key.py
```
The first line is the FERNET_KEY and the second line is the SECRET_KEY.

2. Set the following environment variables within your directory using the terminal:
```
export FERNET_KEY=<generated_fernet_key>
export SECRET_KEY=<your_secret_key>
export EMAIL_PASSWORD=<your_email_password>
```
The current EMAIL_PASSWORD is ntvbtclkmodbyxvi. (as of dec 2nd)

Note that you can store your fernet and secret keys in fernetkey.txt for your future access.

#### 5. Run the Application
To run the main application, use the following commands within your directory using the terminal:
```
# For the main application
uvicorn main:app --reload

# For the admin panel
python main_admin.py
```
This will start the app in development mode, with automatic reloading enabled.

### Notes
1) Excel Import Issues: If the Excel import doesn’t work, reinstall the necessary dependencies from the documentation. Delete any .shl and .val files that may have been created.
2) Gmail Credentials: Contact the project admin team for updated Gmail credentials of easemyvote@gmail.com if necessary.
3) Domain Adjustments: We have updated the email validation logic to include the professor's email domain. Hence instead of filtering out 'krea.ac.in', we are only filtering out emails with just 'krea'. This change ensures that both students and the professor can access the website. 

### Troubleshooting
1) If you encounter issues with email sending, check the environment variables for accuracy.
2) Ensure you have internet connectivity if your project makes API calls or external requests.
3) Check the project logs for detailed error messages, and consult the documentation for further guidance.


