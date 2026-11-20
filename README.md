# GoRemote

Write Go code, save it, and run it on a remote server, safely. Every user gets their own isolated environment, code is screened for malicious patterns before it runs, and requests are shared across two servers so one busy user doesn't slow down everyone else.

## What it does

- **Run Go code remotely.** Send a program and get its output back.
- **Keep your programs.** Save, edit and delete your code; your programs and their output stay in your account.
- **Stay isolated.** Your code runs in your own container, separate from everyone else's, and idle environments are cleaned up automatically.
- **Block harmful code.** Every submission is checked against a set of rules for malicious patterns, and anything flagged is rejected before it runs.
- **Stay responsive.** Requests are spread across two execution servers.

## About the project

GoRemote was built as a group project for CSE540 Cloud Computing at Ahmedabad University by Dhairya Shah, Aayushi Shah, Khwahish Patel, Krishang Shah and Vraj Desai.

---

How it's built, the API and how to run it: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
