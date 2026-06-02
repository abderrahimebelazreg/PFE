# Bibio

Run the project with:

```powershell
python server.py
```

Then open `http://127.0.0.1:8000`.

Default admin login:

- Username: `admin`
- Password: `Admin123!`

Public signup now uses email verification:

1. Open `http://127.0.0.1:8000/signup.html`
2. Fill in the form
3. Receive the 6-digit code by email
4. Enter the code to finish signup

Gmail settings are read from `.env`. Copy `.env.example` to `.env` and set your Gmail address plus Google app password.
