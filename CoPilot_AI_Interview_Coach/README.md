# InterviewProAI — Real-Time Interview Coach

A local-first project starter with:
- Browser microphone transcription using the Web Speech API (best support: Chrome/Edge).
- Live transcript and simple pacing/filler-word feedback.
- Resume analysis for `.pdf`, `.docx`, `.txt`, and `.md` files.
- Role- and technology-specific questions, per-answer coaching, and a final report.
- A two-path interview setup, spoken and on-screen questions, and microphone or typed answers.
- On-device facial framing and expression presentation tips during the interview.
- STAR-style response hints and local fallbacks, with OpenAI API support.
- SQLite persistence for sessions, transcript chunks, resume text, and hints.
- REST endpoints and a single-page dashboard served by FastAPI.

## Important scope and privacy notes
This is a **working MVP**, not a production-certified application. Browser speech recognition availability and behavior depend on browser/OS. The browser Web Speech API may use the browser vendor's online speech service; it is not guaranteed to be local/offline. The app uses the microphone for browser speech recognition and the camera for preview and on-device cues; it does not save raw audio or video recordings. Capturing system/meeting audio reliably across Zoom/Meet/Teams requires a separately permissioned desktop app or platform-specific integration and is intentionally not silently captured. Get consent before recording or transcribing other participants.

Facial presentation tips require camera permission plus an explicit checkbox. Face landmarks are processed in the browser; video frames are not saved or sent to the server. The face-analysis JavaScript and model are downloaded from jsDelivr and Google-hosted MediaPipe assets, so facial tips need an internet connection. Tips are limited to face framing and a natural-smile prompt; they are not emotion/personality recognition and do not contribute to the candidate score. Question audio uses browser speech synthesis.

Transcript, uploaded resume text, analysis, interview answers, and feedback are saved in local `copilot.db` by default. Do not use real sensitive interview data until you have reviewed the storage and retention behavior. You can delete the local database file to remove stored data. If `OPENAI_API_KEY` is configured, resume text, selected role/technologies, interview questions, and answers may be sent to OpenAI for analysis, question generation, and feedback.

## Authentication and account management
- Signed-out visitors are redirected to `/login`; the sign-up form is available at `/signup`. The dashboard is served only after the backend validates the session, including at `/dashboard` and `/static/index.html`.
- New accounts are signed in immediately after successful registration. The authenticated sidebar shows the user's name and a visible **Logout** button.
- The signed-in workspace provides Dashboard, Start Interview, Interview History, Performance Reports, My Profile, and Settings views.
- Passwords are hashed with bcrypt and stored in the SQLite `users` table. Session identifiers are server-side records; the browser receives an HttpOnly, SameSite=Lax session cookie that is not persistent across a normal browser close.
- Sessions expire after 8 hours by default (`AUTH_SESSION_TTL_SECONDS=28800`). The server validates the session on protected page and API requests, and logout invalidates that session. Mutating API requests must have a same-origin `Origin` or `Referer`.
- Set `APP_ENV=production` (or `SESSION_COOKIE_SECURE=true`) when serving the application over HTTPS to enable the cookie's `Secure` attribute. Do not expose the development HTTP server directly to the public internet.
- Protected interview routes enforce ownership checks so a signed-in user can only access their own data. Legacy unowned interviews remain private and are not assigned to new users. On the first startup after this session-policy change, existing sessions are invalidated and users must log in again.

## Requirements
- Python 3.10+
- Chrome or Edge for microphone speech recognition
- OpenAI API key for resume analysis, question generation, answer evaluation, and hints (local fallbacks work without it)

## Run on Windows
1. Extract the ZIP.
2. Double-click `run_windows.bat`.
3. Wait for dependencies to install and the server to start.
4. Open `http://127.0.0.1:8000` in Chrome or Edge on the computer.
5. To open the page on a phone, connect it to the same trusted Wi-Fi network as the computer, find the computer's IPv4 address with `ipconfig`, and open `http://<computer-ipv4>:8000` on the phone (for example, `http://192.168.1.25:8000`). Do not use `127.0.0.1` on the phone; that address points back to the phone itself.
6. Log in or create an account. The Dashboard shows your account-owned practice activity.
7. Open **Start Interview**, enable the camera and microphone, and then select **Start My Interview** to create a session and choose a question source.
8. **Choose technologies** is the first question-source option. Resume upload is at the end of Interview setup and can be selected as the second question-source option. If you choose a resume before uploading one, add it there and select **Start My Interview** again to reopen the prompt.
9. Both camera and microphone must be ready before the first interview question. You can turn devices off during preparation or the interview; voice answers require the microphone, and typed answers remain available.
10. Questions appear beneath the centered camera preview and are read aloud; **Your progress** and **Live transcript** appear below the question. Submit voice or typed answers for feedback; interview progress and question scores update after each evaluation. The completion screen summarizes saved results, and reports remain available under **Performance Reports**.
11. Review saved sessions under **Interview History**, report feedback under **Performance Reports**, and edit account details under **My Profile**.

## Run on macOS/Linux
```bash
chmod +x run_mac_linux.sh
./run_mac_linux.sh
```
Then open `http://127.0.0.1:8000` on the computer. For a phone on the same trusted Wi-Fi, use `http://<computer-ipv4>:8000` (find the address with `ip addr` or `ifconfig`).

To run directly from the project directory after installing `requirements.txt`, use `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.

## AI hints
1. Stop the server.
2. Open `.env` and set `OPENAI_API_KEY=your_key_here`.
3. Restart the server.
The model name is configurable through `OPENAI_MODEL`. API usage can incur charges. Never commit `.env`.

## Database
SQLite database is created automatically at the path in `DATABASE_PATH` (default `./copilot.db`). Tables:
- `users`
- `user_sessions`
- `sessions`
- `transcript_chunks`
- `hints`
- `resumes`
- `interview_answers`
- `performance_reports`

Existing SQLite files are migrated in place with nullable ownership and interview/profile metadata columns. Existing sessions without an owner remain unassigned and are not shown to newly registered accounts. Resume contents are stored in SQLite; this application does not currently write uploaded resumes to a separate file directory.

## API endpoints
- `GET /api/health`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `PATCH /api/auth/me`
- `DELETE /api/auth/me`
- `POST /api/auth/password`
- `GET /api/dashboard`
- `GET /api/sessions`
- `DELETE /api/sessions/{session_id}`
- `GET /api/sessions/{session_id}/report`
- `POST /api/sessions`
- `GET /api/sessions/{session_id}`
- `POST /api/sessions/{session_id}/transcript`
- `POST /api/sessions/{session_id}/resume`
- `POST /api/sessions/{session_id}/resume/analyze`
- `GET /api/interview/options`
- `POST /api/sessions/{session_id}/interview/start`
- `POST /api/sessions/{session_id}/interview/answer`
- `POST /api/sessions/{session_id}/hint`
- `POST /api/sessions/{session_id}/performance`
- `POST /api/sessions/{session_id}/end`
- `GET /api/sessions/{session_id}/export`

## Troubleshooting
- If speech recognition is unavailable, use Chrome/Edge and check microphone permissions.
- After enabling the microphone, click **Start listening** if speech-to-text does not start with the interview. The live transcript uses the browser's Web Speech service, which may require internet access; check the on-screen microphone status for permission or network errors, then retry or type your answer.
- If AI hints fail or no API key is configured, local hints are returned.
- If port 8000 is busy, run `python -m uvicorn app.main:app --reload --port 8001`.
- The browser transcription feature may not work on `file://`; open the app via the FastAPI URL.


## Camera and microphone troubleshooting
- Use `http://127.0.0.1:8000` or `http://localhost:8000`. Browsers block camera/microphone on most non-secure HTTP origins; deployed sites must use HTTPS.
- On a phone, `127.0.0.1` is the phone itself, not the computer hosting the app. Use the computer's IPv4 address and keep both devices on the same trusted Wi-Fi. The launcher binds to the local network for this purpose; allow the firewall prompt only on a private/trusted network, and do not expose this unauthenticated practice app to public networks.
- The app page can load over a local-network HTTP address, but mobile browsers generally block camera and microphone access on that origin. Mobile camera/microphone use requires HTTPS with a certificate trusted by the phone. For full microphone/camera support, use the app on the hosting computer at `http://127.0.0.1:8000`, or configure trusted HTTPS for the LAN host.
- In Chrome/Edge, click the site controls icon beside the address bar → Site settings → set Camera and Microphone to Allow, then reload.
- Check Windows Settings → Privacy & security → Camera / Microphone and allow desktop apps to access them.
- Close other apps/tabs that may be using the camera or microphone, and check that the correct devices are selected in browser/OS settings.
- If one device is denied, the app still attempts to enable the other device independently. Use **Enable Camera & Microphone** to retry after changing permissions.
- The app cannot silently bypass a browser permission denial. The user must grant access.
- Resume analysis, question generation, and answer evaluation use local fallbacks when `OPENAI_API_KEY` is not configured. Configure the key in `.env` for richer extraction and dynamic AI coaching.


## Recommended camera and microphone workflow

1. Run the app locally and open `http://127.0.0.1:8000` in Chrome or Edge.
2. Open **Start Interview**, enable both the camera and microphone, and then select **Start My Interview**.
3. Choose **Choose technologies** first, or select **Use my resume**. Resume upload is at the end of Interview setup; after adding one, select **Start My Interview** again to reopen the prompt.
4. The live workspace centers the camera and current question, with progress and the live transcript below them. The microphone can provide speech-to-text for spoken answers; typed answers remain available.
5. Enable on-device camera framing cues if you want them. Video frames stay in the browser, and camera cues do not affect interview scores.
6. Submit each answer for feedback. The progress bar and question-score chart update only after evaluation; the final answer generates the interview report.
7. Download the interview report or select **End Interview** to stop early. Ending early asks for confirmation and preserves saved answers and progress.

Camera/microphone access requires `localhost`/`127.0.0.1` or HTTPS. Check Chrome site settings and the operating system's privacy settings if permission is denied. Speech-to-text uses the browser SpeechRecognition API, which is best supported in current Chrome and Edge; the microphone input meter is a separate test that confirms the browser can read microphone audio.
