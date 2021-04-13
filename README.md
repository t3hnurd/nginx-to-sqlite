# nginx-to-sqlite
Break default-formatted Nginx logs into a neatly formatted SQLite database

## To Run
`python3 nginx-to-sqlite.py`

This currently checks for any gzipped or standard log files in the same directory (.gz, .log) for processing. The sqlite3 package may be required if it is not installed.
`pip install pysqlite3`

## Expected Output
- A nginx_logs.db SQLite database file
- Terminal output documenting any missed lines

## TODO
- Modify regex to accept all HTTP request methods, rather than the whitelisted ones
- Add proper CLI argument handling for directory path, output DB, input file(s), etc.
- Deduplicate for loop
- Drop missed lines into error output file
- Correctly handle Nginx log lines missing a User Agent string (these are missed, for now)

Tested on a dataset exceeding 50 million lines.
