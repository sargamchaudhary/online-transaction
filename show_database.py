import sqlite3

def show_database():
    # Connect to the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Execute a SELECT query to fetch data
    cursor.execute("SELECT * FROM users")

    # Fetch all rows from the query result
    rows = cursor.fetchall()

    # Print the fetched data
    print("Users:")
    for row in rows:
        print(row)

    # Close the cursor and connection
    cursor.close()
    conn.close()

if __name__ == "__main__":
    show_database()
