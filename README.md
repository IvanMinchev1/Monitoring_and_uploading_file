# MOVEit Transfer Mac File Watcher

This project is a **macOS** application that:
1. **Monitors** a local folder using **FSEvents**.
2. **Safely handles partial file writes** (waits until files are stable before uploading).
3. **Uploads** new or modified files to **MOVEit Transfer** via its REST API, using:
   - **Username/password** authentication (`POST /api/v1/auth/token`)
   - A **folder ID** (e.g., homeFolderID from `/api/v1/users/self`)
   - A **file ID–based approach** for handling modifications (deletes old file by ID before re-uploading).
4. **Maintains** a **history log** (request/response + parsed parameters) in the same folder, ignoring that log file in the watcher logic.

## Features
- **Partial-Write Safe**: The program waits ~3 seconds after a file change before uploading, ensuring you don’t upload half-written files.  
- **MOVEit File ID–Based** Deletion: Uses the **exact** `fileId` returned by MOVEit on upload, so it never deletes the wrong file.  
- **Naive JSON Parsing**: String searches for `"access_token"`, `"homeFolderID"`, and `"id":"..."`.  
- **History Log**: Captures all requests, responses, and key parsed parameters in `history_log.txt`. This file is ignored by the FSEvents monitor.

## Requirements
- **macOS** (for FSEvents and CommonCrypto).  
- **libcurl** installed (e.g., via [Homebrew](https://brew.sh/): `brew install curl`).

## Building
1. **Install** libcurl, e.g. `brew install curl` (if not already installed). 

2. **Running** 

                clang++ main.cpp \
                    -std=c++17 \
                     -lcurl \
                    -framework CoreServices \
                    -framework CommonCrypto \
                    -o moveit_file_watcher

3. **if its not running try this**

                clang++ main.cpp \
                    -std=c++17 \
                    -lcurl \
                    -framework CoreServices \
                    -o moveit_file_watcher



