# Saved Library

A private notes and image library in a single file (`main.py`), built with FastAPI and MongoDB. Each email gets its own isolated library.

## Features

- **Email login:** no password and no sign-up. Enter an email to open that email's library.
- **Isolated data:** every email sees and deletes only its own items.
- **One place to add things:** paste (Ctrl+V), drag and drop, or upload images and text, then press **Save**. Nothing needs a name.
- **Text file:** type a file name and some text, then save it. It can be downloaded as `.txt`.
- **Date-wise list:** items are grouped by day, oldest first by default (switchable). Date and time are taken automatically from the browser.
- **Search and filters:** search text, filter by date range and by type (text or images).
- **NEW tag:** shown on the card corner and removed after 24 hours.
- **Same-page viewer:** click an item to open it with an X button, previous/next arrows, keyboard and swipe support, and a thumbnail strip.
- **Dashboard stats:** total items, images, text items, and new in the last 24 hours.

## Requirements

- Python 3.9+
- A running MongoDB server

No `requirements.txt` is needed. Missing packages (`fastapi`, `uvicorn`, `pymongo`, `python-multipart`, `email-validator`) are installed automatically on first run.

## Run

```bash
python main.py
```

Open http://127.0.0.1:8000

## Configuration (optional environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `MONGO_URL` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB` | `personal_library` | Database name |
| `MAX_IMAGE_MB` | `10` | Maximum image size |
| `SESSION_DAYS` | `30` | How long a login lasts |
| `COOKIE_SECURE` | `0` | Set to `1` when served over HTTPS |
| `PORT` | `8000` | Server port |

PowerShell example:

```powershell
$env:MONGO_URL = "mongodb+srv://USER:PASSWORD@cluster.mongodb.net"
python main.py
```

Keep real database credentials in environment variables, never in the code.

## Data

The database and collections are created automatically on first use:

- `users`: one record per email
- `sessions`: login sessions, which expire automatically
- `saved_items`: notes, text files and image records
- `library_images`: image bytes

## Security note

Login uses the email only, so anyone who knows an email address can open that library. This is fine for personal use. Before putting it online, add a one-time code sent by email.
