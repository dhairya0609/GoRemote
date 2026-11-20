# GoRemote

A remote code execution platform for Go. Users sign in, save Go programs and run them in their own Docker container. An ontology-based check screens code for malicious patterns before it runs, and nginx spreads requests across two execution servers, one written in Go and one in Rust.

Built as a group project for CSE540 Cloud Computing at Ahmedabad University.

## How it works

```
Client ──► Ontology check (Python, OWL)  ──► nginx (round-robin)
                                               ├─► Go server   (chi)        ─┐
                                               └─► Rust server (actix-web)  ─┼─► Docker container per user
                                                                             └─► MongoDB (users, code, output)
```

1. The client signs in with email and password. Passwords are stored as SHA-3 hashes in MongoDB.
2. Submitted code goes to the ontology service, which checks it against rules in an OWL dataset and rejects anything flagged as malicious.
3. nginx forwards the request to one of the two execution servers in turn.
4. The server reuses the user's container or creates one, copies the code in, runs it and returns the output. The code and its output are saved to MongoDB.
5. Containers idle for 10 minutes are stopped and removed; a background job checks every 5 minutes.

## API (Go server)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/register`, `/login`, `/logout` | Account and session |
| `POST` | `/new` | Save a new program |
| `GET` | `/get-files`, `/get-code` | List programs, read one |
| `PUT` | `/update-code` | Edit a program |
| `DELETE` | `/delete-code` | Delete a program |
| `POST` | `/execute`, `/run` | Run code in the user's container |

The Rust server implements the same account and execution flow with actix-web.

## Repository layout

```
go-server/    Go execution server (chi, Docker SDK, MongoDB driver)
rs-server/    Rust execution server (actix-web, Docker, MongoDB)
nginx/        Load balancer config for the two servers
data/         Ontology service (Flask + rdflib), OWL dataset and data generators
```

## Tech

Go, Rust, Python, Docker, MongoDB, nginx, OWL/RDF (rdflib), Flask.

## Deployment used for the project

| Machine | Role |
|---|---|
| Router VM | nginx load balancer and reverse proxy |
| Execution VM 1 | Go server and Docker |
| Execution VM 2 | Rust server and Docker |
| Database VM | MongoDB |

Each VM had 2 CPUs and 4 GB of RAM. The IP addresses in `nginx/nginx.conf` and `data/ontology.py` are from that lab network; change them to run it elsewhere.

## Ideas not built

A web editor, support for more languages, rate limiting, and live container metrics.

## Team

Dhairya Shah, Aayushi Shah, Khwahish Patel, Krishang Shah and Vraj Desai.
