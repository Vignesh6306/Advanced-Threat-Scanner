import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  url TEXT, 
                  safety_score INTEGER, 
                  classification TEXT, 
                  timestamp TEXT)''')
    conn.commit()
    conn.close()

def save_scan(url, score, classification):
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (url, safety_score, classification, timestamp) VALUES (?, ?, ?, ?)", 
              (url, score, classification, now))
    conn.commit()
    conn.close()

def get_history():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute("SELECT id, url, safety_score, classification, timestamp FROM history ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def delete_record(record_id):
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute("DELETE FROM history WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

def clear_history():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute("DELETE FROM history")
    conn.commit()
    conn.close()
